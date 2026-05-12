# frozen_string_literal: true

# Discourse SAML Plugin for AMA (Autenticacao.gov)
# Version: 1.1

# 1. Global Patch (defined but only active via Thread-Local)
after_initialize do
  require "onelogin/ruby-saml/authrequest"
  require "omniauth-saml"

  class OneLogin::RubySaml::Authrequest
    unless method_defined?(:original_create_xml_doc)
      alias_method :original_create_xml_doc, :create_xml_doc

      def create_xml_doc(settings, params = {})
        doc = original_create_xml_doc(settings, params)

        if Thread.current[:ama_saml_patch_enabled]
          puts "AMA: Global create_xml_doc patch EXECUTING!"
          
          fa_ns = "http://autenticacao.cartaodecidadao.pt/atributos"
          root = doc.root
          extensions = root.elements["samlp:Extensions"] || root.add_element("samlp:Extensions")
          
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

  # Load other components
  require_relative "lib/ama_authnrequest_extension"
  require_relative "lib/discourse_saml/saml_omniauth_strategy"
  require_relative "lib/discourse_saml/saml_replay_cache"
  
  puts "AMA: SamlAuthenticator components loaded"
end

# 2. Authenticator registration (Top Level)
require_relative "lib/saml_authenticator"

# Use ENV directly to ensure settings are available during the build phase
title = ENV["DISCOURSE_SAML_TITLE"] || "SAML"
button_title = ENV["DISCOURSE_SAML_BUTTON_TITLE"] || title

auth_provider icon_setting: :saml_icon,
              title: button_title,
              pretty_name: title,
              authenticator: SamlAuthenticator.new
