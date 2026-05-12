# frozen_string_literal: true

class ::DiscourseSaml::SamlOmniauthStrategy < OmniAuth::Strategies::SAML
  option :request_method, "GET"

  def request_phase
    puts "AMA: SAML Strategy request_phase started. Method: #{options[:request_method]}"

    with_settings do |settings|
      authn_request = OneLogin::RubySaml::Authrequest.new

      # Direct injection of AMA extensions
      if ::DiscourseSaml.setting(:ama_enabled)
        original_method = authn_request.method(:create_xml_doc)
        authn_request.define_singleton_method(:create_xml_doc) do |settings, params|
          puts "AMA: Singleton create_xml_doc called!"
          doc = original_method.call(settings, params)
          
          fa_ns = "http://autenticacao.cartaodecidadao.pt/atributos"
          root = doc.root
          extensions = root.elements["samlp:Extensions"] || root.add_element("samlp:Extensions")
          
          # Ensure correct order (after Issuer)
          if root.elements["saml:Issuer"] && extensions.parent == root
            # Already in root, but let's make sure it's after Issuer
            issuer = root.elements["saml:Issuer"]
            root.delete_element(extensions)
            root.insert_after(issuer, extensions)
          end

          level = ::DiscourseSaml.setting(:ama_faaalevel) || "3"
          extensions.add_element("fa:FAAALevel", { "xmlns:fa" => fa_ns }).text = level.to_s
          
          req_attrs = extensions.add_element("fa:RequestedAttributes", { "xmlns:fa" => fa_ns })
          (::DiscourseSaml.setting(:ama_requested_attributes) || "").split("|").map(&:strip).each do |attr_name|
            next if attr_name.empty?
            req_attrs.add_element("fa:RequestedAttribute", {
              "Name" => attr_name,
              "NameFormat" => "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
              "isRequired" => "False"
            })
          end
          doc
        end
      end

      if options[:request_method] == "POST"
        params = authn_request.create_params(settings, additional_params_for_authn_request)
        destination = settings.idp_sso_service_url
        render_auto_submitted_form(destination: destination, params: params)
      else
        super
      end
    end
  end

  def callback_phase
    if request.request_method.downcase.to_sym == :post && !request.params["SameSite"] &&
         request.params["SAMLResponse"]
      env[Rack::RACK_SESSION_OPTIONS][:skip] = true # Do not set any session cookies. They'll override our SameSite ones

      # Make browser re-issue the request in a same-site context so we get cookies
      # For this particular action, we explicitly **want** cross-site requests to include session cookies
      render_auto_submitted_form(
        destination: callback_url,
        params: {
          "SAMLResponse" => request.params["SAMLResponse"],
          "SameSite" => "1",
        },
      )
    else
      super
    end
  end

  def extra
    # extra[:response_object] contains a field `document` which breaks the to_json call in OmniAuthCallbacksController.persist_auth_token
    # with a SystemStackError. We don't actually use extra[:response_object] anywhere so just exclude it
    super.except(:response_object)
  end

  # Override parent's find_attribute_by to skip blank values
  # This prevents empty SAML attributes from overriding valid ones when
  # attribute_statements maps multiple SAML attributes to the same field
  def find_attribute_by(keys)
    keys.each do |key|
      value = @attributes[key]
      return value if value.present?
    end
    nil
  end

  protected

  def handle_response(raw_response, opts, settings)
    super do
      if SiteSetting.saml_replay_protection_enabled && @response_object &&
           !DiscourseSaml::SamlReplayCache.valid?(@response_object)
        Rails.logger.warn(
          "SAML Debugging: replay attempt detected for ID: #{@response_object.response_id}, name: #{@response_object.name_id}",
        )
        return fail!(:saml_assertion_replay_detected)
      end
      yield
    end
  end

  private

  def render_auto_submitted_form(destination:, params:)
    response_headers = { "content-type" => "text/html" }

    submit_script_url =
      UrlHelper.absolute(
        "#{Discourse.base_path}/plugins/discourse-saml/javascripts/submit-form-on-load.js",
        GlobalSetting.cdn_url,
      )

    inputs = params.map { |key, value| <<~HTML }.join("\n")
        <input type="hidden" name="#{CGI.escapeHTML(key)}" value="#{CGI.escapeHTML(value)}"/>
      HTML

    html = <<~HTML
      <html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en">
        <body>
          <noscript>
            <p>
              <strong>Note:</strong> Since your browser does not support JavaScript,
              you must press the Continue button once to proceed.
            </p>
          </noscript>
          <form action="#{CGI.escapeHTML(destination)}" method="post">
            <div>
              #{inputs}
            </div>
            <noscript>
              <div>
                <input type="submit" value="Continue"/>
              </div>
            </noscript>
          </form>
          <script src="#{CGI.escapeHTML(submit_script_url)}" nonce="#{ContentSecurityPolicy.try(:nonce_placeholder, response_headers)}"></script>
        </body>
      </html>
    HTML

    r = Rack::Response.new(html, 200, response_headers)
    r.finish
  end
end
