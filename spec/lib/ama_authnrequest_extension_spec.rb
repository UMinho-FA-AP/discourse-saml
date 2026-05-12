# frozen_string_literal: true

require 'rails_helper'

describe DiscourseSaml::AmaAuthnrequestExtension do
  let(:settings) { OneLogin::RubySaml::Settings.new }
  let(:auth_request) { OneLogin::RubySaml::Authrequest.new }

  before do
    SiteSetting.saml_ama_enabled = true
    SiteSetting.saml_ama_faaalevel = "3"
    SiteSetting.saml_ama_requested_attributes = "http://interop.gov.pt/MDC/Cidadao/NIC|http://interop.gov.pt/MDC/Cidadao/NomeProprio"
  end

  it "injects AMA extensions when enabled" do
    doc = auth_request.create_xml_doc(settings)
    xml = doc.to_s

    expect(xml).to include('<samlp:Extensions>')
    expect(xml).to include('<fa:FAAALevel xmlns:fa="http://autenticacao.cartaodecidadao.pt/atributos">3</fa:FAAALevel>')
    expect(xml).to include('<fa:RequestedAttributes xmlns:fa="http://autenticacao.cartaodecidadao.pt/atributos">')
    expect(xml).to include('Name="http://interop.gov.pt/MDC/Cidadao/NIC"')
    expect(xml).to include('Name="http://interop.gov.pt/MDC/Cidadao/NomeProprio"')
    expect(xml).to include('NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"')
    expect(xml).to include('isRequired="False"')
  end

  it "does not inject AMA extensions when disabled" do
    SiteSetting.saml_ama_enabled = false
    doc = auth_request.create_xml_doc(settings)
    xml = doc.to_s

    expect(xml).not_to include('<samlp:Extensions>')
    expect(xml).not_to include('fa:FAAALevel')
  end

  it "respects custom FAAALevel and attributes" do
    SiteSetting.saml_ama_faaalevel = "4"
    SiteSetting.saml_ama_requested_attributes = "http://example.com/attr1"
    
    doc = auth_request.create_xml_doc(settings)
    xml = doc.to_s

    expect(xml).to include('fa:FAAALevel')
    expect(xml).to include('>4</fa:FAAALevel>')
    expect(xml).to include('Name="http://example.com/attr1"')
    expect(xml).not_to include('Name="http://interop.gov.pt/MDC/Cidadao/NIC"')
  end

  it "does not duplicate extensions if called multiple times on the same document" do
    # This might happen if ruby-saml internal flow calls it twice, 
    # though create_xml_doc usually creates a fresh one.
    doc = auth_request.create_xml_doc(settings)
    
    # Simulate a second call manually
    auth_request.send(:create_xml_doc, settings) 
    
    xml = doc.to_s
    expect(xml.scan('<samlp:Extensions>').length).to eq(1)
    expect(xml.scan('fa:FAAALevel').length).to eq(1)
  end
end
