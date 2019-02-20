
class AzureEventHubsHttpSender
  def initialize(connection_string,hub_name,uri,secure_access_signature,sas_expiration,secure_access_policy_name,expiry=3600,proxy_addr='',proxy_port=3128,open_timeout=60,read_timeout=60)
    require 'openssl'
    require 'base64'
    require 'net/http'
    require 'json'
    require 'cgi'
    require 'time'
    require 'httpclient'
    @connection_string = connection_string
    @hub_name = hub_name
    @uri = uri
    @secure_access_signature = secure_access_signature
    @sas_expiration = sas_expiration
    @secure_access_policy_name = secure_access_policy_name
    @expiry_interval = expiry
    @proxy_addr = proxy_addr
    @proxy_port = proxy_port
    @open_timeout = open_timeout
    @read_timeout = read_timeout

    valid_connection_string = lambda { [2,3].include?@connection_string.count(';') }
    valid_sas = lambda { [@uri, @secure_access_signature, @secure_access_policy_name].all?{|x| x.length > 0} }

    if !valid_connection_string.call and !valid_sas.call
      raise "Valid connection_string or [uri, secure_access_signature, sas_expiration, secure_access_policy_name] must be provided"
    end

    if valid_connection_string.call
      @connection_string.split(';').each do |part|
        if ( part.index('Endpoint') == 0 )
          @endpoint = 'https' + part[11..-1]
        elsif ( part.index('SharedAccessKeyName') == 0 )
          @secure_access_policy_name = part[20..-1]
        elsif ( part.index('SharedAccessKey') == 0 )
          @sas_key_value = part[16..-1]
        elsif ( part.index('EntityPath') == 0 )
          @hub_name = part[11..-1]
        end
      end

      if [@endpoint, @secure_access_policy_name, @sas_key_value, @hub_name].any?{|v| v == nil || v == "" }
        raise "Connection String is missing required information"
      end

      @uri = URI.parse("#{@endpoint}#{@hub_name}/messages")
    
    else #valid_sas
      @uri = URI.parse(uri)
      @token = generate_sas_auth_header(@uri.to_s, @secure_access_signature, @sas_expiration, @secure_access_policy_name)
    end

    if (proxy_addr.to_s.empty?)
      @client = HTTPClient.new
    else
      proxy_url = "#{proxy_addr}:#{proxy_port}"
      @client = HTTPClient.new(proxy)
    end
  end

  def generate_sas_auth_header(target_uri, signature, expiry, key_name)
    encoded_uri = CGI.escape(target_uri)
    encoded_signature = CGI.escape(signature)
    token = "SharedAccessSignature sr=#{encoded_uri}&sig=#{encoded_signature}&se=#{expiry}&skn=#{key_name}"
    return token
  end

  def generate_secure_access_signature(uri, expiry_interval, key_value)
    target_uri = CGI.escape(uri)
    expiry = Time.now.to_i + expiry_interval
    to_sign = "#{target_uri}\n#{expiry}";
    signature = Base64.encode64(OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'), key_value, to_sign)).strip()
    return signature, expiry
  end

  private :generate_secure_access_signature
  private :generate_sas_auth_header

  def send(payload)
    send_w_properties(payload, nil)
  end

  def send_w_properties(payload, properties)
    if @token.nil? || @sas_expiration < Time.now.to_i
      @signature, @sas_expiration = generate_secure_access_signature(@uri.to_s, @expiry_interval, @sas_key_value)
      @token = generate_sas_auth_header(@uri.to_s, @signature, @sas_expiration, @secure_access_policy_name)
    end

    headers = {
      'Content-Type' => 'application/atom+xml;type=entry;charset=utf-8',
      'Authorization' => @token
    }
    if not properties.nil?
      headers = headers.merge(properties)
    end
    body = payload.to_json
    res = @client.post(@uri.to_s, body, headers)
    if res.status >= 300
      raise "Error while sending message, status=#{res.status}"
    end
  end
end
