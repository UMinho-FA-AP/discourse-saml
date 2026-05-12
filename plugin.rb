# frozen_string_literal: true
# name: discourse-saml
# about: SAML Auth Provider with Portugal Autenticacao.gov (AMA) support
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

# Patch module for AMA Extensions support
module AmaAuthrequestPatch
  # We override create_xml_doc to modify the XML before it is signed or encoded
  def create_xml_doc(settings, params = {})
    doc = super(settings, params)
    
    if Thread.current[:ama_saml_patch_enabled]
      require "rexml/document"
      
      fa_ns = "http://autenticacao.cartaodecidadao.pt/atributos"
      root = doc.root
      
      # Find or create Extensions
      extensions = root.elements["samlp:Extensions"] || root.add_element("samlp:Extensions")
      
      # Ensure Extensions is correctly positioned (after Issuer)
      if root.elements["saml:Issuer"] && extensions.parent == root
        issuer = root.elements["saml:Issuer"]
        root.delete_element(extensions)
        root.insert_after(issuer, extensions)
      end

      # Add FAAALevel
      level = Thread.current[:ama_faaalevel] || "3"
      extensions.add_element("fa:FAAALevel", { "xmlns:fa" => fa_ns }).text = level.to_s
      
      # Add RequestedAttributes
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

  # Prepend the patch to the Authrequest class
  OneLogin::RubySaml::Authrequest.prepend(AmaAuthrequestPatch)

  require_relative "lib/discourse_saml/saml_omniauth_strategy"
  require_relative "lib/saml_authenticator"
end

require_relative "lib/saml_authenticator"

title = ENV["DISCOURSE_SAML_TITLE"] || "SAML"
button_title = ENV["DISCOURSE_SAML_BUTTON_TITLE"] || title

auth_provider name: "saml",
              icon_setting: :saml_icon,
              title: button_title,
              pretty_name: title,
              authenticator: AmaSamlAuthenticator.new
