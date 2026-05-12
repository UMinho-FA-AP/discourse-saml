# frozen_string_literal: true

require "onelogin/ruby-saml/authrequest"

module DiscourseSaml
  module AmaAuthnrequestExtension
    # This patch injects custom <samlp:Extensions> required by Portugal's AMA (Autenticacao.gov)
    # as specified in their SAML profile.
    #
    # The AMA IdP requires specific attributes and a FAALevel to be present in the AuthnRequest
    # extensions block, otherwise it rejects the request with a generic error.
    #
    # Namespace: http://autenticacao.cartaodecidadao.pt/atributos
    def create_xml_doc(settings, params = {})
      doc = super

      return doc unless ::DiscourseSaml.setting(:ama_enabled)

      fa_ns = "http://autenticacao.cartaodecidadao.pt/atributos"

      root = doc.root
      
      # samlp namespace is defined by ruby-saml as urn:oasis:names:tc:SAML:2.0:protocol
      extensions = root.elements["samlp:Extensions"] || root.add_element("samlp:Extensions")

      # Add FAAALevel
      # Level 3 is typically required for Chave Móvel Digital / Citizen Card authentication.
      level = ::DiscourseSaml.setting(:ama_faaalevel) || "3"
      unless extensions.elements["fa:FAAALevel"]
        faaa_level = extensions.add_element("fa:FAAALevel", { "xmlns:fa" => fa_ns })
        faaa_level.text = level.to_s
      end

      # Add RequestedAttributes
      # These define which user attributes we are requesting from the AMA IdP.
      unless extensions.elements["fa:RequestedAttributes"]
        req_attrs = extensions.add_element("fa:RequestedAttributes", { "xmlns:fa" => fa_ns })
        
        attributes = (::DiscourseSaml.setting(:ama_requested_attributes) || "").split("|").map(&:strip).reject(&:blank?)
        attributes.each do |attr_name|
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

OneLogin::RubySaml::Authrequest.prepend(DiscourseSaml::AmaAuthnrequestExtension)
