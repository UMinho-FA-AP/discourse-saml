# frozen_string_literal: true

require "onelogin/ruby-saml/authrequest"

# This WILL show up in stdout during startup
puts "AMA: Loading Autenticacao.gov extension patch..."

# Diagnostic log to confirm the file is being loaded during Discourse startup
Rails.logger.warn("AMA: Patch file lib/ama_authnrequest_extension.rb is being loaded!") if defined?(Rails) && Rails.logger

module DiscourseSaml
  module AmaAuthnrequestExtension
    # This patch injects custom <samlp:Extensions> required by Portugal's AMA (Autenticacao.gov)
    # as specified in their SAML profile.
    #
    # The AMA IdP requires specific attributes and a FAALevel to be present in the AuthnRequest
    # extensions block, otherwise it rejects the request with a generic error.
    #
    # Namespace: http://autenticacao.cartaodecidadao.pt/atributos
    private
    def create(settings, params = {})
      puts "AMA: Authrequest#create called!"
      super
    end

    def create_xml_doc(settings, params = {})
      # Diagnostic log to confirm the method is being intercepted
      puts "AMA: create_xml_doc called! AMA Enabled: #{::DiscourseSaml.setting(:ama_enabled)}"
      if defined?(Rails) && Rails.logger
        Rails.logger.warn("AMA: create_xml_doc called! AMA Enabled: #{::DiscourseSaml.setting(:ama_enabled)}")
      end

      doc = super

      return doc unless ::DiscourseSaml.setting(:ama_enabled)

      fa_ns = "http://autenticacao.cartaodecidadao.pt/atributos"
      root = doc.root
      
      # SAML 2.0 schema requires samlp:Extensions to be after saml:Issuer and before 
      # samlp:Subject, samlp:NameIDPolicy, etc. 
      # ruby-saml's default #add_element appends to the end, which breaks schema validation.
      extensions = root.elements["samlp:Extensions"]
      
      unless extensions
        # Identify the first element that should come AFTER Extensions
        # Reference: https://www.oasis-open.org/committees/download.php/11511/sstc-saml-schema-protocol-2.0.xsd
        following_element = root.elements["samlp:Subject"] || 
                            root.elements["samlp:NameIDPolicy"] || 
                            root.elements["samlp:Conditions"] ||
                            root.elements["samlp:RequestedAuthnContext"] ||
                            root.elements["samlp:Scoping"]
        
        if following_element
          extensions = REXML::Element.new("samlp:Extensions")
          root.insert_before(following_element, extensions)
        else
          extensions = root.add_element("samlp:Extensions")
        end
      end

      # Add FAAALevel with inline namespace to match your image
      level = ::DiscourseSaml.setting(:ama_faaalevel) || "3"
      unless extensions.elements["fa:FAAALevel"]
        faaa_level = extensions.add_element("fa:FAAALevel", { "xmlns:fa" => fa_ns })
        faaa_level.text = level.to_s
      end

      # Add RequestedAttributes with inline namespace to match your image
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

