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

module AmaAuthrequestPatch
  def create_params(settings, params = {})
    puts "AMA: create_params intercepting! Patch enabled: #{Thread.current[:ama_saml_patch_enabled].inspect}"
    
    result = super(settings, params)
    
    if Thread.current[:ama_saml_patch_enabled] && result["SAMLRequest"]
      require "rexml/document"
      require "base64"
      require "zlib"
      
      puts "AMA: Decoding SAMLRequest for extension injection..."
      
      # Detect if it is deflated (standard for GET/Redirect) or raw (standard for POST)
      begin
        decoded = Base64.decode64(result["SAMLRequest"])
        begin
          # Try inflating
          inflated = Zlib::Inflate.new(-Zlib::MAX_WBITS).inflate(decoded)
          is_deflated = true
        rescue
          # If inflation fails, it might be raw XML
          inflated = decoded
          is_deflated = false
        end
        
        doc = REXML::Document.new(inflated)
        root = doc.root
        fa_ns = "http://autenticacao.cartaodecidadao.pt/atributos"
        
        # Don't apply twice
        if root.elements["//fa:FAAALevel"]
          puts "AMA: Extensions already present, skipping."
          return result
        end

        puts "AMA: Injecting extensions (is_deflated: #{is_deflated})"
        
        extensions = root.elements["samlp:Extensions"] || REXML::Element.new("samlp:Extensions")
        
        # Position correctly: After Signature if present, else after Issuer
        signature = root.elements["//ds:Signature"]
        issuer = root.elements["//saml:Issuer"]
        
        if signature
          puts "AMA: Signature found, placing extensions after it."
          root.insert_after(signature, extensions)
        elsif issuer
          puts "AMA: No signature, placing extensions after issuer."
          root.insert_after(issuer, extensions)
        else
          root.add_element(extensions)
        end

        # Add AMA fields
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

        # Re-encode
        new_xml = String.new
        doc.write(new_xml)
        
        if is_deflated
          deflated = Zlib::Deflate.new(nil, -Zlib::MAX_WBITS).deflate(new_xml, Zlib::FINISH)
          result["SAMLRequest"] = Base64.strict_encode64(deflated)
        else
          result["SAMLRequest"] = Base64.strict_encode64(new_xml)
        end
        puts "AMA: SAMLRequest successfully patched."
        
      rescue => e
        puts "AMA: ERROR during injection: #{e.message}\n#{e.backtrace.first(5).join("\n")}"
      end
    end
    
    result
  end
end

after_initialize do
  require "onelogin/ruby-saml/authrequest"
  require "omniauth-saml"

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
