module Auth20

  def self.included(base)
    base.class_eval do
      before do
        # unless request.path_info =~ /login|\/api|favicon/
        #   halt 401 if (request.path_info =~ /\/oauth_back\/me/) && request.cookies['authenticated'].nil?
        #   redirect '/oauth_back/login' if request.cookies['authenticated'].nil?
        #   # redirect '/login' if request.cookies['authenticated'].nil? && request.path_info != '/login'
        # end
        # if request.path_info =~ /\/api/
        #   # initialize
        # end
      end

      after do
        if request.path_info =~ /\/api/
          # @kc.logout
        end
      end

      ajax_call :get, '/oauth_back/me' do
        access_token = request.cookies['token']
        token = JWT.decode access_token, '', false, algorithm: 'RS256'
        # user_groups = @kc.user_groups(KC_REALM, token[0]['sub'])
        token[0]
      end

      get('/oauth_back/login') do
        slim :login, layout: false
      end

      ajax_call :post, '/oauth_back/login' do |payload|
        halt 401 unless get_token payload
      end

      ajax_call :get, '/oauth_back/refresh' do |payload|
        halt 401 unless refresh
      end

      get('/oauth_back/logout') do
        logout
        redirect '/oauth_back/login'
      end

    end
  end
end