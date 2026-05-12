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

# Utility module for AMA XML injection logic
module AmaXmlExtension
  def self.apply!(doc)
    return unless Thread.current[:ama_saml_patch_enabled]
    
    require "rexml/document"
    fa_ns = "http://autenticacao.cartaodecidadao.pt/atributos"
    root = doc.root
    
    # Don't apply twice if already present with our level
    return if root.elements["samlp:Extensions"] && root.elements["samlp:Extensions"].elements["fa:FAAALevel"]

    # 1. Ensure Extensions exist
    extensions = root.elements["samlp:Extensions"] || REXML::Element.new("samlp:Extensions")
    
    # 2. Position correctly: Standard order is Issuer, Signature, Extensions
    signature = root.elements["ds:Signature"]
    issuer = root.elements["saml:Issuer"]
    
    if signature
      # If signature exists, put extensions AFTER it as per AMA example
      root.insert_after(signature, extensions)
    elsif issuer
      # Otherwise put after issuer
      root.insert_after(issuer, extensions)
    else
      # Fallback to end of root
      root.add_element(extensions) unless extensions.parent
    end

    # 3. Add/Update FAAALevel
    faaalevel = extensions.elements["fa:FAAALevel"] || extensions.add_element("fa:FAAALevel", { "xmlns:fa" => fa_ns })
    faaalevel.text = (Thread.current[:ama_faaalevel] || "3").to_s
    
    # 4. Add/Update RequestedAttributes
    req_attrs = extensions.elements["fa:RequestedAttributes"] || extensions.add_element("fa:RequestedAttributes", { "xmlns:fa" => fa_ns })
    
    existing_names = req_attrs.get_elements("fa:RequestedAttribute").map { |el| el.attributes["Name"] }
    (Thread.current[:ama_requested_attributes] || "").split("|").map(&:strip).reject(&:empty?).each do |attr_name|
      next if existing_names.include?(attr_name)
      req_attrs.add_element("fa:RequestedAttribute", {
        "Name" => attr_name,
        "NameFormat" => "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
        "isRequired" => "False"
      })
    end
  end
end

# Patch 1: The Signing Utility
# This ensures extensions are added BEFORE the XML is signed
module AmaSignPatch
  def add_sign(doc, *args)
    AmaXmlExtension.apply!(doc) if Thread.current[:ama_saml_patch_enabled]
    super(doc, *args)
  end
end

# Patch 2: The Authrequest Class
# This ensures extensions are added even if the request is NOT signed
module AmaAuthrequestPatch
  def create_xml_doc(settings, params = {})
    doc = super(settings, params)
    AmaXmlExtension.apply!(doc) if Thread.current[:ama_saml_patch_enabled]
    doc
  end
end

after_initialize do
  require "onelogin/ruby-saml/authrequest"
  require "onelogin/ruby-saml/utils"
  require "omniauth-saml"

  # Apply both patches to ensure extensions are added correctly in all flows
  OneLogin::RubySaml::Utils.singleton_class.prepend(AmaSignPatch)
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
