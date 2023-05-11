require 'sinatra'
require 'sinatra/reloader'
require 'slim'
require 'bcrypt'

require_relative './model.rb'

# NEEDS TO BE STORED IN SESSION
# $error_obj = Mer::ErrorHandler.new

# db = Mer::Database.new(DB_PATH)
# user = Mer::User.new(db.get)
# user.create_root

# before do 
#     if session[:id].nil? && !AUTH.include?(request.path_info) && request.path_info != '/error'
#       session[:error] = 'You need to be logged in'
#       redirect('/error')
#     elsif !session[:id].nil? && AUTH.include?(request.path_info)
#       p 'redirecting to previous action'
#       redirect(session[:action])
#     end
# end

enable :sessions

DB_PATH ||= 'db/database.db'

NOT_SIGNED_IN_ALLOWED ||= ['/login', '/register']
# FIX PERMS
NOT_SIGNED_IN_DISALLOWED ||= ['/users', '/rooms/']
ADMIN_ONLY ||= ['/admin']

# create admin account on initialization
# -> todo!!!
# p.s. do it directly from Database class...

def handle_error(error_message)
    Mer::ErrorHandler.register(session, error_message)
    request.path_info = '/'
    redirect('/error')
end

before do
    path_info = request.path_info
    puts path_info

    if NOT_SIGNED_IN_DISALLOWED.include?(path_info) && Mer::Authorization.signed_in?(session)
        if not Mer::Authorization.valid?(session)
            handle_error(Mer::ErrorMessage::CREDENTIALS_INVALID)
        end
    end

    if request.get?
        if NOT_SIGNED_IN_ALLOWED.include?(path_info) && Mer::Authorization.signed_in?(session)
            handle_error(Mer::ErrorMessage::ALREADY_SIGNED)
        elsif NOT_SIGNED_IN_DISALLOWED.include?(path_info) && !Mer::Authorization.signed_in?(session)
            handle_error(Mer::ErrorMessage::NEED_SIGNED)
        elsif ADMIN_ONLY.include?(path_info) && !Mer::Authorization.admin?(session)
            handle_error(Mer::ErrorMessage::UNAUTHORIZED)
        end
    end
end

after do
    if request.get? && !request.path_info.include?('error')
        if response.status == 404
            puts "setting previous action to '/'"
            Mer::ErrorHandler.register(session, Mer::ErrorMessage::NOT_FOUND)
            session[:action] = '/'
            redirect('/error')
        else
            puts "setting previous action to #{request.path_info}"
            session[:action] = request.path_info
        end
    end
end

get('/error') do 
    session[:action] = '/' if session[:action].nil?
    p "previous action was: #{session[:action]}"
    slim(:error)
end

get('/') do
    redirect('/login')
end

#############
# PRE-LOGIN #
############# 

get('/login') do
    slim(:login)
end

get('/register') do
    slim(:"users/new")
end

post('/users') do    
    username = params[:username]
    password = params[:password]
    password_confirm = params[:password_confirm]

    if password != password_confirm
        Mer::ErrorHandler.register(session, Mer::ErrorMessage::PASSWORD_DIFFERENT)
        redirect('/error')
    end

    user_obj = Mer::User.new(session)
    begin
        user_obj.register(username, password, Mer::UserType::USER)
    rescue
        redirect('/error')
    end
end

post('/login') do
    username = params[:username]
    password = params[:password]

    user_obj = Mer::User.new(session)
    begin
        user_obj.login(username, password)
        redirect('/rooms/')
    rescue => e
        puts e.message
        redirect('/error')
    end
end

##############
# POST-LOGIN #
# -> user    #
##############

get('/signout') do 
    session.clear
    redirect('/')
end

##############
# POST-LOGIN #
# -> user    #
#    -> :id  #
##############

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

##############
# POST-LOGIN #
# -> rooms   #
##############a

get('/rooms/') do
    id = session[:user][:id]

    db = Mer::Database.new
    selected_tags = params[:tags]
  
    if selected_tags && selected_tags.any?
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
  
    @tags = db.select("tags", "*")

    slim(:"rooms/index")
end  

get('/rooms/new') do
    db = Mer::Database.new
    @tags = db.select("tags", "*")
    slim(:"rooms/new")
end

get('/rooms/login') do 
    slim(:"rooms/login")
end

post('/rooms') do 
    db = Mer::Database.new
    name = params[:name]
    tags = params[:tags]

    room_obj = Mer::Room.new(session)
    begin
        room_obj.register(name, tags)
        redirect('/rooms/')
    rescue => e
        puts e
        redirect('/error')
    end


    # db = Database::connect(DB_PATH)
    # name = params[:name]
    # tag_ids = params[:tags]
    # owner_id = session[:id]

    # if name.length > 16
    #     p "name length"
    #     session[:error] = "The room name must be at most 16 characters long."
    #     redirect('/error')
    # end

    # if tag_ids.nil?
    #     p "no tags provided"
    #     session[:error] = "A room needs to have tags."
    #     redirect('/error')
    # end

    # invite = unique_invite()

    # db.execute("INSERT INTO room(name, invite, owner_id) VALUES (?, ?, ?)", name, invite, owner_id)
    # room_id = db.last_insert_row_id

    # tag_ids.each do |tag_id|
    #     tag = tag_id.to_i
    #     db.execute("INSERT INTO room_tags_relation(room_id, tag_id) VALUES (?, ?)", room_id, tag)
    # end    

    # # maybe add a check?
    # db.execute("INSERT INTO room_user_relation(room_id, user_id) VALUES (?, ?)", room_id, owner_id)
    
    # redirect('/rooms/')
end

post('/rooms/login') do 
    invite = params[:invite]

    room_obj = Mer::Room.new(session)
    begin
        room_obj.login(invite)
        redirect('/rooms/')
    rescue => e
        puts e.message
        redirect('/error')
    end

    # db = Database::connect(DB_PATH)
    # user_id = session[:id]
    # room_invite = params[:invite]

    # if room_invite.empty?
    #     session[:error] = "The invite was empty."
    #     redirect('/error')
    # end

    # if room = db.execute("SELECT * FROM room WHERE invite = ?", room_invite).first
    #     if db.execute("SELECT * FROM room_user_relation WHERE room_id=? AND user_id=?", room["id"], user_id).first
    #         session[:error] = "You are already a member of that room"
    #         redirect('/error')
    #     else
    #         db.execute("INSERT INTO room_user_relation(room_id, user_id) VALUES (?, ?)", room["id"], user_id)
    #         redirect('/rooms/')
    #     end  
    # else
    #     session[:error] = "Room doesn't exist"
    #     redirect('/error')
    # end
end

##############
# POST-LOGIN #
# -> rooms   #
#    -> :id  #
##############

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

# get('/rooms/:id/edit') do 
#     session[:prev_action] = request.path_info
#     # check permissions
# end

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

# post('/rooms/:id/update') do 
#     # check permissions
# end

post('/rooms/:id/delete') do 
    # check permissions
end

##############
# POST-LOGIN #
# -> message #
##############

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

##############
# POST-LOGIN #
# -> message #
#    -> :id  #
##############

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

##############
# POST-LOGIN #
# -> admin   #
##############

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

##############
# POST-LOGIN #
# -> tags    #
##############

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