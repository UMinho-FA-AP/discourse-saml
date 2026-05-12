# frozen_string_literal: true
# name: discourse-saml
# about: SAML Auth Provider
# version: 1.1
# authors: Discourse, INOV
# url: https://github.com/UMinho-FA-AP/discourse-saml

# Diagnostic patch to find out what is nil during activation
class Plugin::Instance
  unless method_defined?(:original_activate!)
    alias_method :original_activate!, :activate!
    def activate!
      puts "AMA: activate! starting. Providers: #{@auth_providers.inspect}"
      original_activate!
    rescue => e
      puts "AMA: CRASH in activate!: #{e.message}"
      puts "AMA: Backtrace: #{e.backtrace.first(10).join("\n")}"
      raise e
    end
  end
end

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

  require_relative "lib/discourse_saml/saml_omniauth_strategy"
  require_relative "lib/saml_authenticator"
  
  puts "AMA: SamlAuthenticator components loaded"
end

require_relative "lib/saml_authenticator"

title = ENV["DISCOURSE_SAML_TITLE"] || "SAML"
button_title = ENV["DISCOURSE_SAML_BUTTON_TITLE"] || title

auth_provider name: "saml",
              icon_setting: :saml_icon,
              title: button_title,
              pretty_name: title,
              authenticator: AmaSamlAuthenticator.new
