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
  def create_xml_doc(settings, params = {})
    doc = super(settings, params)
    return doc unless Thread.current[:ama_saml_patch_enabled]

    require "rexml/document"

    fa_ns = "http://autenticacao.cartaodecidadao.pt/atributos"
    root = doc.root

    signature = root.elements["ds:Signature"]
    extensions = root.elements["samlp:Extensions"]

    unless extensions
      extensions = REXML::Element.new("samlp:Extensions")

      if signature
        signature.next_sibling = extensions
      else
        issuer = root.elements["saml:Issuer"]
        if issuer
          issuer.next_sibling = extensions
        else
          root.add_element(extensions)
        end
      end
    end

    faaalevel = extensions.elements["fa:FAAALevel"]
    unless faaalevel
      faaalevel = extensions.add_element(
        "fa:FAAALevel",
        { "xmlns:fa" => fa_ns }
      )
    end
    faaalevel.text = (Thread.current[:ama_faaalevel] || "3").to_s

    req_attrs = extensions.elements["fa:RequestedAttributes"]
    unless req_attrs
      req_attrs = extensions.add_element(
        "fa:RequestedAttributes",
        { "xmlns:fa" => fa_ns }
      )
    end

    existing_names =
      req_attrs.get_elements("fa:RequestedAttribute").map { |el| el.attributes["Name"] }

    (Thread.current[:ama_requested_attributes] || "")
      .split("|")
      .map(&:strip)
      .reject(&:empty?)
      .each do |attr_name|
        next if existing_names.include?(attr_name)

        req_attrs.add_element(
          "fa:RequestedAttribute",
          {
            "Name" => attr_name,
            "NameFormat" => "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
            "isRequired" => "False",
          }
        )
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
