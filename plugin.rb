# frozen_string_literal: true

# Discourse SAML Plugin for AMA (Autenticacao.gov)
# Version: 1.1

after_initialize do
  # By this point, all gems (including ruby-saml) are fully loaded
  class OneLogin::RubySaml::Authrequest
    unless method_defined?(:original_create_xml_doc)
      alias_method :original_create_xml_doc, :create_xml_doc

      def create_xml_doc(settings, params = {})
        doc = original_create_xml_doc(settings, params)

        # Only apply AMA modifications if explicitly enabled for this thread
        if Thread.current[:ama_saml_patch_enabled]
          puts "AMA: Global create_xml_doc patch EXECUTING!"
          
          fa_ns = "http://autenticacao.cartaodecidadao.pt/atributos"
          root = doc.root
          extensions = root.elements["samlp:Extensions"] || root.add_element("samlp:Extensions")
          
          # Ensure correct order (after Issuer)
          if root.elements["saml:Issuer"] && extensions.parent == root
            issuer = root.elements["saml:Issuer"]
            root.delete_element(extensions)
            root.insert_after(issuer, extensions)
          end

          level = Thread.current[:ama_faaalevel] || "3"
          extensions.add_element("fa:FAAALevel", { "xmlns:fa" => fa_ns }).text = level.to_s
          
          req_attrs = extensions.add_element("fa:RequestedAttributes", { "xmlns:fa" => fa_ns })
          (Thread.current[:ama_requested_attributes] || "").split("|").map(&:strip).each do |attr_name|
            next if attr_name.empty?
            req_attrs.add_element("fa:RequestedAttribute", {
              "Name" => attr_name,
              "NameFormat" => "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
              "isRequired" => "False"
            })
          end
        end
        
        doc
      end
    end
  end

  module ::DiscourseSaml::SessionControllerExtensions
    def login_error_check(user)
      if ::DiscourseSaml.is_saml_forced_domain?(user.email)
        return { error: I18n.t("login.use_saml_auth") }
      end
      super
    end
  end
  ::SessionController.prepend(::DiscourseSaml::SessionControllerExtensions)

  # "SAML Forced Domains" - Prevent login via other omniauth strategies
  class ::DiscourseSaml::ForcedSamlError < StandardError
  end
  on(:after_auth) do |authenticator, result|
    next if authenticator.name == "saml"
    if [result.user&.email, result.email].any? { |e| ::DiscourseSaml.is_saml_forced_domain?(e) }
      raise ::DiscourseSaml::ForcedSamlError
    end
  end
  Users::OmniauthCallbacksController.rescue_from(::DiscourseSaml::ForcedSamlError) do
    flash[:error] = I18n.t("login.use_saml_auth")
    render("failure")
  end
  
  puts "AMA: SamlAuthenticator initialized"
end

require_relative "lib/ama_authnrequest_extension"
require_relative "lib/discourse_saml/saml_omniauth_strategy"
require_relative "lib/discourse_saml/saml_replay_cache"
require_relative "lib/saml_authenticator"

# Allow GlobalSettings to override the translations
name = GlobalSetting.try(:saml_title)
button_title = GlobalSetting.try(:saml_button_title) || GlobalSetting.try(:saml_title)

auth_provider icon_setting: :saml_icon,
              title: button_title,
              pretty_name: name,
              authenticator: SamlAuthenticator.new
