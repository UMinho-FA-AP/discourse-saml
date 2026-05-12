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
    unless Thread.current[:ama_saml_patch_enabled]
      puts "AMA: apply! skipped because patch_enabled is false/nil"
      return
    end
    
    puts "AMA: apply! EXECUTING on document..."
    
    require "rexml/document"
    fa_ns = "http://autenticacao.cartaodecidadao.pt/atributos"
    root = doc.root
    
    # Check for existing level using local-name to avoid prefix issues
    if root.elements["//*[local-name()='FAAALevel']"]
      puts "AMA: FAAALevel already present, skipping injection."
      return
    end

    # 1. Ensure Extensions exist
    extensions = root.elements["//*[local-name()='Extensions']"] || REXML::Element.new("samlp:Extensions")
    
    # 2. Position: After Issuer (Signature will be added by the library later)
    issuer = root.elements["//*[local-name()='Issuer']"]
    if issuer
      puts "AMA: Found Issuer, inserting extensions after it."
      root.insert_after(issuer, extensions)
    else
      puts "AMA: No Issuer found, adding extensions to root."
      root.add_element(extensions)
    end

    # 3. Add AMA fields
    puts "AMA: Adding FAAALevel and RequestedAttributes..."
    level = Thread.current[:ama_faaalevel] || "3"
    extensions.add_element("fa:FAAALevel", { "xmlns:fa" => fa_ns }).text = level.to_s
    req_attrs = extensions.add_element("fa:RequestedAttributes", { "xmlns:fa" => fa_ns })
    (Thread.current[:ama_requested_attributes] || "").split("|").map(&:strip).reject(&:empty?).each do |attr_name|
      req_attrs.add_element("fa:RequestedAttribute", {
        "Name" => attr_name,
        "NameFormat" => "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
        "isRequired" => "False"
      })
    end
    puts "AMA: apply! completed successfully."
  rescue => e
    puts "AMA: CRASH in apply!: #{e.message}\n#{e.backtrace.first(5).join("\n")}"
  end
end

# Patch 1: The Signing Utility
module AmaSignPatch
  def add_sign(doc, *args)
    puts "AMA: OneLogin::RubySaml::Utils.add_sign INTERCEPTED"
    AmaXmlExtension.apply!(doc) if Thread.current[:ama_saml_patch_enabled]
    super(doc, *args)
  end
end

# Patch 2: The Authrequest Class
module AmaAuthrequestPatch
  def create_xml_doc(settings, params = {})
    puts "AMA: OneLogin::RubySaml::Authrequest#create_xml_doc INTERCEPTED"
    doc = super(settings, params)
    AmaXmlExtension.apply!(doc) if Thread.current[:ama_saml_patch_enabled]
    doc
  end
end

after_initialize do
  require "onelogin/ruby-saml/authrequest"
  require "onelogin/ruby-saml/utils"
  require "omniauth-saml"

  puts "AMA: Applying patches..."
  OneLogin::RubySaml::Utils.singleton_class.prepend(AmaSignPatch)
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
