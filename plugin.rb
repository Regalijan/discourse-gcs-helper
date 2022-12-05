# frozen_string_literal: true

# name: discourse-gcs-helper
# about: Helper plugin for Discourse and Google Cloud Storage
# version: 0.0.1
# author: Wolftallemo
# url: https://github.com/Wolftallemo/discourse-gcs-helper

require 'cgi'
require 'json'
require 'jwt'
require 'net/http'

after_initialize do
  module GCSHelper
    @access_token
    @access_token_expiration = 0
    def self.compose_multipart_object(key, bucket, access_token)
      uri = URI("https://storage.googleapis.com/storage/v1/b/#{bucket}/o/#{CGI.escape(key)}")
      response = Net::HTTP.start uri.host, uri.port, use_ssl: true do |http|
        request = Net::HTTP::Get.new uri
        request['authorization'] = "Bearer #{access_token}"

        http.request request
      end

      unless response.is_a?(Net::HTTPSuccess)
        raise "Something very weird happened: #{response.body}"
      end

      obj_to_compose = JSON.parse(response.body)
      compose_uri = URI("https://storage.googleapis.com/storage/v1/b/#{bucket}/o/#{CGI.escape(key)}/compose")
      compose_response = Net::HTTP.post compose_uri, {
                                                  kind: 'storage#compose',
                                                  sourceObjects: [
                                                    {
                                                      name: key
                                                    }
                                                  ],
                                                  destination: obj_to_compose
                                                }.to_json, {
                       'authorization' => "Bearer #{access_token}",
                       'content-type' => 'application/json'
                     }

      unless compose_response.is_a?(Net::HTTPSuccess)
        raise "Failed to compose object: #{compose_response.body}"
      end
    end

    def self.get_access_token
      if @access_token && @access_token_expiration > Time.now.to_i + 10
        return @access_token
      end

      credentials_file = File.read(ENV["STORAGE_CREDENTIALS_PATH"] || "/shared/gcs.json")
      data = JSON.parse(credentials_file)
      now = Time.now.to_i
      pkey = OpenSSL::PKey::RSA.new data['private_key']
      payload = {
        aud: 'https://oauth2.googleapis.com/token',
        exp: now + 3600,
        iat: now,
        iss: data['client_email'],
        scope: 'https://www.googleapis.com/auth/devstorage.full_control'
      }

      jwt = JWT.encode payload, pkey, 'RS256'

      access_token_response = Net::HTTP.post_form(
        URI('https://oauth2.googleapis.com/token'),
       {
         'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
         'assertion' => jwt
       }
      )

      raise "Google returned an error: #{access_token_response.body}" unless
        access_token_response.is_a?(Net::HTTPSuccess)

      data = JSON.parse(access_token_response.body)
      @access_token = data['access_token']
      @access_token_expiration = Time.now.to_i + data['expires_in']

      @access_token
    end

    def self.normalize_acl(acl)
      normalized_acls = {
        'bucket-owner-full-control': 'bucketOwnerFullControl',
        'private': 'private',
        'public-read': 'publicRead'
      }

      normalized_acls[acl]
    end

    def self.rewrite_request(key, destination, bucket, access_token, options: {})
      rewrite_opts = {
        cacheControl: options[:cache_control],
        contentDisposition: options[:content_disposition],
        contentType: options[:content_type]
      }

      rewrite_opts.compact!

      res = Net::HTTP.post URI(
                             "https://storage.googleapis.com/storage/v1/b/#{
                               bucket
                             }/o/#{CGI.escape(key)}/rewriteTo/b/#{
                               bucket
                             }/o/#{CGI.escape(destination)}#{
                               options[:acl] &&
                                 options[:apply_metadata_to_destination] ?
                                 "?destinationPredefinedAcl=#{GCSHelper.normalize_acl(
                                   options[:acl]
                                 )}" : ""
                             }"
                           ), options[:apply_metadata_to_destination] &&
                             rewrite_opts.size > 0 ? rewrite_opts.to_json : '',
                           {
                             'authorization' => "Bearer #{access_token}",
                             'content-type' => 'application/json'
                           }

      res
    end
  end

  class ::S3Helper
    def copy(source, destination, options: {})
      destination = get_path_for_s3_upload(destination)
      key = if !Rails.configuration.multisite ||
        source.include?(multisite_upload_path) ||
        source.include?(@tombstone_prefix)

        source
      elsif @s3_bucket_folder_path
        folder, filename = source.split("/", 2)

        File.join(folder, multisite_upload_path, filename)
      else
        File.join(multisite_upload_path, source)
      end

      access_token = GCSHelper.get_access_token
      rewrite_res = GCSHelper.rewrite_request(key, destination, @s3_bucket_name, access_token, options)

      unless rewrite_res.is_a?(Net::HTTPSuccess)
        begin
          error_code = JSON.parse(rewrite_res.body)['error']['errors'][0]['reason']
        rescue
          raise "An error was returned by Google! Status: #{rewrite_res.code}; Body: #{rewrite_res.body}"
        end

        # At the moment, Google does not support rewriting objects uploaded via multipart
        # Those objects must be composed first before they can be rewritten
        # Google returns the 'invalid' code for those objects
        unless error_code == 'invalid'
          raise "Google returned an error: #{rewrite_res.body}"
        end

        GCSHelper.compose_multipart_object key, @s3_bucket_name, access_token
        rewrite_res = GCSHelper.rewrite_request(key, destination, @s3_bucket_name, access_token, options)
      end

      [
        destination,
        JSON.parse(
          rewrite_res.body
        )['resource']['etag']
      ]
    end

    def delete_objects(keys)
      # As bad as this is, this is the only way
      # Google does not support deleting
      # multiple objects at a time
      keys.each do |key|
        object_uri = URI("https://storage.googleapis.com/storage/v1/b/#{@s3_bucket_name}/o/#{CGI.escape(key)}")

        Net::HTTP.start(object_uri.host, object_uri.port, use_ssl: true) do |http|
          req = Net::HTTP::Delete.new object_uri
          req['authorization'] = "Bearer #{GCSHelper.get_access_token}"

          http.request req
        end
      end
    end

    def update_lifecycle(_id, days, prefix: nil, tag: nil)
      lifecycle = {
        lifecycle: {
          rule: [
            {
              action: {
                type: 'Delete'
              },
              condition: {
                age: days,
                prefix: prefix
              }
            }
          ]
        }
      }

      lifecycle.compact!

      uri = URI("https://storage.googleapis.com/storage/v1/b/#{@s3_bucket_name}?fields=lifecycle")
      req = Net::HTTP::Patch.new uri
      req['authorization'] = "Bearer #{GCSHelper.get_access_token}"
      req['content-type'] = 'application/json'
      req.body = JSON.generate lifecycle
      res = Net::HTTP.start(uri.host, uri.port, use_ssl: true) do |http|
        http.request req
      end

      unless res.is_a?(Net::HTTPSuccess)
        raise "Failed to update lifecycle: #{res.body}"
      end
    end
  end
end
