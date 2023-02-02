require 'sinatra'
require 'sinatra/reloader'
require 'slim'
require 'bcrypt'

require_relative './model.rb'

enable :sessions
DB_PATH ||= 'db/database.db'

before do 
    p request.path_info
    if (session[:id] == nil) && !['/', '/error', '/login', '/register'].include?(request.path_info)
        session[:error] = "You need to be logged in"
        redirect('/error')
    end
end

after do 
    if (request.path_info != '/error')
        # session[:prev_action] = request.path_info
    end
end

get('/error') do 
    @error_message = session[:error]
    @prev_action = session[:prev_action]
    p @prev_action
    slim(:error)
end

get('/') do
    redirect('/login')
end

get('/login') do
    session[:prev_action] = request.path_info
    slim(:login)
end

post('/login') do
    db = Database::connect(DB_PATH)
    username = params[:username]
    password = params[:password]
  
    result = db.execute("SELECT * FROM user WHERE username=?", username).first
    if result
      pw_digest = result["pw_digest"]
      id = result["id"]
  
      if BCrypt::Password.new(pw_digest) == password
        session[:id] = id
        redirect('/rooms')
      else  
        # wrong password
        session[:error] = "Wrong password"
        redirect('/error')
      end
    else  
      # user doesn't exist
      session[:error] = "User doesn't exist"
      redirect('/error')
    end
  end

get('/register') do
    session[:prev_action] = request.path_info
    slim(:"users/new")
end

get('/users/') do 
    session[:prev_action] = request.path_info
    p "inside users"
    slim(:"users/index")
end

post('/users') do
    db = Database::connect(DB_PATH)
    username = params[:username]
    password = params[:password]
    password_confirm = params[:password_confirm]

    result = db.execute("SELECT id FROM user WHERE username=?", username)
    if result.empty?
        if (password == password_confirm)
          pw_digest = BCrypt::Password.create(password)
          
          db.execute("INSERT INTO user(username, pw_digest) VALUES (?, ?)", username, pw_digest)
          redirect('/')
        else 
            # passwords don't match
            session[:error] = "Password doesn't match"
            redirect('/error')
        end
    else  
        # username doesn't exist
        session[:error] = "User doesn't exist"
        redirect('/error')
    end
end

get('/rooms') do
    session[:prev_action] = request.path_info
    db = Database::connect(DB_PATH)
    slim(:"rooms/index")
end



# ge varje room en kategori 
# för att få ytterliggare en relationstabell

# låt också det finnas viss användar
# behövrighet 