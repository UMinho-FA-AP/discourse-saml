# frozen_string_literal: true
# name: discourse-saml
# about: SAML Auth Provider
# version: 1.1
# authors: Discourse, INOV
# url: https://github.com/UMinho-FA-AP/discourse-saml

gem "ruby-saml", "1.18.0"
gem "omniauth-saml", "2.2.3"

module ::DiscourseSaml
  def self.setting(key, default = nil)
    SiteSetting.send("saml_#{key}")
  rescue NoMethodError
    GlobalSetting.try("saml_#{key}")
  end
end

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

# Define the patch module outside after_initialize for clarity
module AmaAuthrequestPatch
  def create_params(settings, params = {})
    puts "AMA: create_params PREPENDed intercepting! Patch enabled: #{Thread.current[:ama_saml_patch_enabled].inspect}"
    
    # We still want to modify the XML, so we will actually override create_xml_doc here
    # but we will also log that we are in create_params
    super(settings, params)
  end

  def create_xml_doc(settings, params = {})
    puts "AMA: create_xml_doc PREPENDed intercepting! Patch enabled: #{Thread.current[:ama_saml_patch_enabled].inspect}"
    doc = super(settings, params)
    
    if Thread.current[:ama_saml_patch_enabled]
      puts "AMA: Global create_xml_doc patch EXECUTING!"
      # ... (rest of the XML logic remains the same)
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

after_initialize do
  require "onelogin/ruby-saml/authrequest"
  require "omniauth-saml"

  # Apply the patch using prepend
  OneLogin::RubySaml::Authrequest.prepend(AmaAuthrequestPatch)

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
