require 'sinatra'
require 'sinatra/reloader'
require 'slim'
require 'bcrypt'

require_relative './model.rb'

enable :sessions
DB_PATH ||= 'db/database.db'

AUTH = ['/', '/error', '/login', '/register', '/users', '/retry']

before do 
    db = Database::connect(DB_PATH)
    result = db.execute("SELECT id FROM user WHERE username=?", "admin")
    if result.empty?
          pw_digest = BCrypt::Password.create("admin")
          
          db.execute("INSERT INTO user(username, pw_digest) VALUES (?, ?)", "admin", pw_digest)
    end
    p request.path_info

    if (session[:id] == nil) && !AUTH.include?(request.path_info)
        session[:error] = "You need to be logged in"
        redirect('/error')
    elsif (session[:id] != nil) && AUTH.include?(request.path_info)
        redirect(session[:prev_action])
    end
end

after do 
    if (request.path_info != '/error')
        # session[:prev_action] = request.path_info
    end
end

# post eller get?
post('/retry') do
    p "retry detected"
    if session[:prev_action]
        p "previous action found"
        redirect(session[:prev_action])
    else
        p "previous not action found"
        redirect('/')
    end
end

get('/error') do 
    @error_message = session[:error]
    @prev_action = session[:prev_action]
    p "previous action was: #{@prev_action}"
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

    if username.empty? || password.empty?
        session[:error] = "One of the parameters were empty."
        redirect('/error')
    end
  
    result = db.execute("SELECT * FROM user WHERE username=?", username).first
    if result
      pw_digest = result["pw_digest"]
      id = result["id"]
  
      if BCrypt::Password.new(pw_digest) == password
        session[:id] = id
        redirect('/rooms/')
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

    db = Database::connect(DB_PATH)
    id = session[:id]
    result = db.execute("SELECT * FROM user WHERE id=?", id).first


    @username = result["username"]

    slim(:"users/index")
end

post('/users') do
    db = Database::connect(DB_PATH)
    username = params[:username]
    password = params[:password]
    password_confirm = params[:password_confirm]

    if username.empty? || password.empty? || password_confirm.empty?
        session[:error] = "One of the parameters were empty."
        redirect('/error')
    end

    if username.scan(/\s/) || password.scan(/\s/)
        session[:error] = "One of the parameters had a whitespace character in it."
        redirect('/error')
    end

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

get('/rooms/') do
    session[:prev_action] = request.path_info
    db = Database::connect(DB_PATH)
    slim(:"rooms/index")
end


get('/rooms/new') do
    session[:prev_action] = request.path_info
    db = Database::connect(DB_PATH)
    @tags = db.execute("SELECT * FROM tags")
    slim(:"rooms/new")
end

post('/rooms') do 
    redirect('/rooms/')
end

get('/admin/') do 
    session[:prev_action] = request.path_info
    slim(:"admin/index")
end

get('/tags/new') do
    session[:prev_action] = request.path_info
    slim(:"tags/new")
end

post('/tags') do 
    # add permission check
    # only admins should be able to create new tags
    db = Database::connect(DB_PATH)
    label = params[:label]

    if label.empty?
        session[:error] = "One of the parameters were empty."
        redirect('/error')
    end

    result = db.execute("SELECT id FROM tags WHERE label=?", label)
    if result.empty?
        db.execute("INSERT INTO tags(label) VALUES (?)", label)
        redirect('/')
    else  
        session[:error] = "Tag already exists"
        redirect('/error')
    end
end

# ge varje room en kategori 
# för att få ytterliggare en relationstabell

# låt också det finnas viss användar
# behövrighet 