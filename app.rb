require 'sinatra'
require 'sinatra/reloader'
require 'slim'
require 'bcrypt'

require_relative './model.rb'

enable :sessions

# REMEMBER TO IMPLEMENT CLEAN UP OF DATA
# IN DATABASE IF THAT DATA IS DELETED

# constants
DB_PATH ||= 'db/database.db'
AUTH = ['/', '', '/login', '/register', '/users', '/retry']

def create_admin_user
  db = Database::connect(DB_PATH)
  result = db.execute("SELECT id FROM user WHERE username=?", "admin")
  if result.empty?
    pw_digest = BCrypt::Password.create("admin")
    db.execute("INSERT INTO user(type, username, pw_digest) VALUES (?, ?, ?)", UserType::ADMIN, "admin", pw_digest)
  end
end

create_admin_user

before do 
    p request.path_info

    if session[:id].nil? && !AUTH.include?(request.path_info) && request.path_info != '/error'
      session[:error] = 'You need to be logged in'
      redirect('/error')
    elsif !session[:id].nil? && AUTH.include?(request.path_info)
      p 'redirecting to previous action'
      redirect(session[:prev_action])
    end
end

post('/retry') do
    p 'retry detected'
    redirect(session[:prev_action] || '/')
end

get('/error') do 
    @error_message = session[:error]
    @prev_action = session[:prev_action]
    p "previous action was: #{@prev_action}"
    slim :error
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
      type = result["type"]
  
      if BCrypt::Password.new(pw_digest) == password
        if type == UserType::ADMIN
            p "admin has logged in"
            session[:admin] = 1 
        end
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

get('/signout') do 
    session.clear
    redirect('/')
end

get('/users/:id/edit') do 
    db = Database::connect(DB_PATH)
    active_user_id = session[:id]
    @user_id = params[:id].to_i

    if @user_id == active_user_id
        slim(:"users/edit")
    else
        session[:error] = "You do not have permission"
        redirect('/error')
    end
end

post('/users/:id/update') do 
    db = Database::connect(DB_PATH)
    active_user_id = session[:id]
    user_id = params[:id].to_i

    if user_id == active_user_id
        username = params[:username]
        db.execute("UPDATE user SET username = ? WHERE id = ?", [username, user_id])
        redirect('/')
    else
        session[:error] = "You do not have permission"
        redirect('/error')
    end
end

post('/users/:id/delete') do 
    db = Database::connect(DB_PATH)
    active_user_id = session[:id]
    user_id = params[:id].to_i

    if user_id == active_user_id
        username = params[:username]
        db.execute("UPDATE user SET username = ? WHERE id = ?", [username, user_id])
        redirect('/')
    else
        session[:error] = "You do not have permission"
        redirect('/error')
    end
end

get('/users/:id') do 
    db = Database::connect(DB_PATH)
    active_user_id = session[:id]
    user_id = params[:id].to_i

    @result = db.execute("SELECT * FROM user WHERE id=?", user_id).first

    if @result.nil?
        session[:error] = "User doesn't exist"
        redirect('/error')
    end

    @active_user_result = db.execute("SELECT * FROM user WHERE id=?", active_user_id).first

    @same_user = false
    @admin = false

    if user_id == active_user_id
        p "same user"
        @same_user = true
    end

    p @result

    if @active_user_result['type'] == UserType::ADMIN
        p "is admin"
        @admin = true
    end

    p @same_user
    p @admin

    session[:prev_action] = request.path_info
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

    if username.scan(/\s/).length > 0 || password.scan(/\s/).length > 0
        session[:error] = "One of the parameters had a whitespace character in it."
        redirect('/error')
    end

    result = db.execute("SELECT id FROM user WHERE username=?", username).first
    if result.nil?
        if (password == password_confirm)
          pw_digest = BCrypt::Password.create(password)
          
          db.execute("INSERT INTO user(username, type, pw_digest) VALUES (?, ?, ?)", username, UserType::USER, pw_digest)
          redirect('/')
        else 
            # passwords don't match
            session[:error] = "Password doesn't match"
            redirect('/error')
        end
    else  
        session[:error] = "User exists"
        redirect('/error')
    end
end

get('/rooms/') do
    id = session[:id]
    db = Database::connect(DB_PATH)
  
    selected_tags = params[:tags]
  
    if selected_tags && selected_tags.any?
      # filter by selected tags
      tag_ids = selected_tags.map(&:to_i).join(',')
      @rooms = db.execute("
        SELECT r.id AS room_id, r.name AS room_name, u.username AS owner_username,
          (SELECT COUNT(DISTINCT user_id) FROM room_user_relation WHERE room_id = r.id) AS member_count,
          r.owner_id
        FROM room AS r
        JOIN user AS u ON u.id = r.owner_id
        JOIN room_user_relation AS rur ON rur.room_id = r.id
        JOIN room_tags_relation AS tr ON tr.room_id = r.id
        WHERE rur.user_id = ? AND tr.tag_id IN (#{tag_ids})
        GROUP BY r.id", id)
    else
      # no tags selected, show all rooms
      @rooms = db.execute("
        SELECT r.id AS room_id, r.name AS room_name, u.username AS owner_username,
          (SELECT COUNT(DISTINCT user_id) FROM room_user_relation WHERE room_id = r.id) AS member_count,
          r.owner_id
        FROM room AS r
        JOIN user AS u ON u.id = r.owner_id
        JOIN room_user_relation AS rur ON rur.room_id = r.id
        WHERE rur.user_id = ?
        GROUP BY r.id", id)
    end
  
    @tags = db.execute("SELECT * FROM tags")
  
    session[:prev_action] = request.path_info
    slim(:"rooms/index")
end  

get('/rooms/:id/edit') do 
    db = Database::connect(DB_PATH)
    active_user_id = session[:id]
    @room_id = params[:id].to_i

    is_member = db.execute("SELECT 1 FROM room_user_relation WHERE room_id = ? AND user_id = ?", @room_id, active_user_id).first
    is_owner = db.execute("SELECT 1 FROM room WHERE id = ? AND owner_id = ?", @room_id, active_user_id).first

    if is_member && is_owner
        slim(:"rooms/edit")
    else
        session[:error] = "You do not have permission"
        redirect('/error')
    end
end

post('/rooms/:id/update') do
    db = Database::connect(DB_PATH)
    active_user_id = session[:id]
    room_id = params[:id].to_i
  
    is_owner = db.execute("SELECT 1 FROM room WHERE owner_id = ? AND id = ?", active_user_id, room_id).first
  
    if is_owner
      new_name = params[:name]
  
      if new_name.empty?
        session[:error] = "Room name cannot be empty"
        redirect('/error')
      elsif new_name.length > 16
        session[:error] = "Room name cannot exceed 16 characters"
        redirect('/error')
      else
        db.execute("UPDATE room SET name = ? WHERE id = ?", new_name, room_id)
        redirect("/rooms/#{room_id}")
      end
    else
      session[:error] = "You do not have permission to update this room"
      redirect('/error')
    end
end

get('/rooms/new') do
    session[:prev_action] = request.path_info
    db = Database::connect(DB_PATH)
    @tags = db.execute("SELECT * FROM tags")
    slim(:"rooms/new")
end

get('/rooms/login') do 
    session[:prev_action] = request.path_info
    slim(:"rooms/login")
end

post('/rooms/login') do 
    db = Database::connect(DB_PATH)
    user_id = session[:id]
    room_invite = params[:invite]

    if room_invite.empty?
        session[:error] = "The invite was empty."
        redirect('/error')
    end

    if room = db.execute("SELECT * FROM room WHERE invite = ?", room_invite).first
        if db.execute("SELECT * FROM room_user_relation WHERE room_id=? AND user_id=?", room["id"], user_id).first
            session[:error] = "You are already a member of that room"
            redirect('/error')
        else
            db.execute("INSERT INTO room_user_relation(room_id, user_id) VALUES (?, ?)", room["id"], user_id)
            redirect('/rooms/')
        end  
    else
        session[:error] = "Room doesn't exist"
        redirect('/error')
    end
end

def unique_invite()
    db = Database::connect(DB_PATH)
    invite = (0...8).map { (65 + rand(26)).chr }.join
    existing_room = db.execute("SELECT * FROM room WHERE invite = ?", invite).first
    if existing_room
        unique_invite()
    end

    return invite
end

post('/rooms') do 
    db = Database::connect(DB_PATH)
    name = params[:name]
    tag_ids = params[:tags]
    owner_id = session[:id]

    if name.length > 16
        p "name length"
        session[:error] = "The room name must be at most 16 characters long."
        redirect('/error')
    end

    if tag_ids.nil?
        p "no tags provided"
        session[:error] = "A room needs to have tags."
        redirect('/error')
    end

    invite = unique_invite()

    db.execute("INSERT INTO room(name, invite, owner_id) VALUES (?, ?, ?)", name, invite, owner_id)
    room_id = db.last_insert_row_id

    tag_ids.each do |tag_id|
        tag = tag_id.to_i
        db.execute("INSERT INTO room_tags_relation(room_id, tag_id) VALUES (?, ?)", room_id, tag)
    end    

    # maybe add a check?
    db.execute("INSERT INTO room_user_relation(room_id, user_id) VALUES (?, ?)", room_id, owner_id)
    
    redirect('/rooms/')
end

get('/rooms/:id') do 
    @user_id = session[:id].to_i

    if @user_id
        @room_id = params[:id].to_i
        db = Database::connect(DB_PATH)
        is_member = db.execute("SELECT 1 FROM room_user_relation WHERE room_id = ? AND user_id = ?", @room_id, @user_id).first

        if is_member
            @room = db.execute("SELECT * FROM room WHERE id = ?", @room_id)

            @messages = db.execute("
                SELECT m.id AS message_id, m.room_id AS message_room_id, m.content AS message_content, m.owner_id AS message_owner, u.username AS message_owner_username
                FROM message AS m
                JOIN user AS u ON u.id = m.owner_id
                WHERE m.room_id = ?
                ", @room_id)
            
            p @messages

            @invite = db.execute("
                SELECT invite FROM room WHERE id = ?
                ", @room_id).first[0]

            session[:prev_action] = request.path_info
            slim(:"rooms/show")
        else
            p "Not a member"
            session[:error] = "You are not a member of this room."
            redirect('/error')
        end
    else
        session[:error] = "You are not logged in."
        redirect('/error')
    end
end

get('/rooms/:id/edit') do 
    session[:prev_action] = request.path_info
    # check permissions
end

post('/rooms/:id/update') do 
    # check permissions
end

post('/rooms/:id/delete') do 
    # check permissions
end

post('/message') do 
    user_id = session[:id].to_i

    if user_id
        room_id = params[:room_id].to_i

        if room_id
            db = Database::connect(DB_PATH)
            p room_id
            p user_id
            is_member = db.execute("SELECT 1 FROM room_user_relation WHERE room_id = ? AND user_id = ?", room_id, user_id).first

            if is_member
                message_content = params[:content]

                if message_content.empty?
                    session[:error] = "Your message was empty."
                    redirect('/error')
                end

                if message_content.length > 200
                    p "message length"
                    session[:error] = "The your message exceded 200 characters."
                    redirect('/error')
                end

                db.execute("INSERT INTO message(content, room_id, owner_id) VALUES (?, ?, ?)", message_content, room_id, user_id)
            else
                p "Not a member"
                session[:error] = "You are not a member of this room."
                redirect('/error')
            end
        else
            session[:error] = "No room_id found."
            redirect('/error')
        end
        
    else
        session[:error] = "You are not logged in."
        redirect('/error')
    end

    redirect('/rooms/' + room_id.to_s)
end

post('/message/:id/delete') do 
    message_id = params[:id].to_i
    db = Database::connect(DB_PATH)

    message = db.execute("SELECT * FROM message WHERE id = ?", message_id).first
    room = db.execute("SELECT * FROM room WHERE id = ?", message['room_id']).first

    if session[:id] == message['user_id'] || session[:id] == room['owner_id']
        db.execute("DELETE FROM message WHERE id = ?", message_id)
        redirect back
    else
        session[:error] = "You do not have permission"
        redirect('/error')
    end
end

get('/admin/') do 
    db = Database::connect(DB_PATH)
    active_user_id = session[:id]

    active_user_result = db.execute("SELECT * FROM user WHERE id=?", active_user_id).first

    puts "current user type: #{active_user_result['type']}\npermitted user type: #{UserType::ADMIN}"

    if active_user_result['type'] == UserType::ADMIN
        p "granted"
        session[:prev_action] = request.path_info
        slim(:"admin/index")
    else
        session[:error] = "You do not have permission"
        redirect('/error')
    end
end

post('/admin/nuke') do
    # CHECK FOR ADMIN USER TYPE
    db = Database::connect(DB_PATH)

    active_user_id = session[:id]
    active_user_result = db.execute("SELECT * FROM user WHERE id=?", active_user_id).first

    if active_user_result['type'] == UserType::ADMIN
        db.execute("DELETE FROM room")
        db.execute("DELETE FROM room_user_relation")
        db.execute("DELETE FROM room_tags_relation")
        db.execute("DELETE FROM message")
    
        redirect('/admin/')
    end

    session[:error] = "You do not have permission"
    redirect('/error')
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

post('/signout') do 
    session.clear
    redirect('/')
end