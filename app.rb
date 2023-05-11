require 'sinatra'
require 'sinatra/reloader'
require 'slim'
require 'bcrypt'

require_relative './model.rb'

enable :sessions

# List of routes allowed when the user is not signed in.
NOT_SIGNED_IN_ALLOWED ||= ['/login', '/register']
# List of routes disallowed when the user is not signed in.
NOT_SIGNED_IN_DISALLOWED ||= ['/users', '/admin', '/rooms', '/message', '/admin', '/tags']
# List of routes accessible only to admins.
ADMIN_ONLY ||= ['/admin', '/tags']

temp_connection = Mer::Database.new
temp_connection.create_root

# Registers an error message and redirects to the error page.
#
# @param [String] error_message The error message to be registered.
def handle_error(error_message)
    Mer::ErrorHandler.register(session, error_message)
    request.path_info = '/'
    redirect('/error')
end

# Runs before every request and checks if the user has access to the requested page.
before do
    path_info = request.path_info
    puts path_info

    if not request.path_info == '/error'
        if Mer::Authorization.signed_in?(session)
            current_time = Time.now.to_i
            refill_rate = 5 # maximum requests per second
            capacity = 5 # maximum tokens in the bucket

            session[:last_request_time] ||= current_time # initialize if nil

            # calculate the number of tokens to refill based on the elapsed time
            tokens_to_add = ((current_time - session[:last_request_time]) * refill_rate).to_i
            session[:last_request_time] = current_time

            # add tokens to the bucket, up to the maximum capacity
            session[:token_bucket] = [(session[:token_bucket] || 0) + tokens_to_add, capacity].min

            if session[:token_bucket].to_i > 0
                # consume a token from the bucket
                session[:token_bucket] -= 1
            else
                # bucket is empty, redirect to error page or handle the error
                Mer::ErrorHandler.register(session, Mer::ErrorMessage::COOLDOWN)
                redirect('/error')
            end
        end
    end

    if not request.post? && request.path_info == '/users' # hacky way of preventing the "blockage" of sign-up requests
        if Mer::Authorization.signed_in?(session)
            if NOT_SIGNED_IN_ALLOWED.any? { |word| path_info.include?(word) }
                # prevent signed-in user to be able to 
                # sign-in or register, they'll have to sign-out
                redirect('/rooms/')
            end

            if ADMIN_ONLY.any? { |word| path_info.include?(word) } && !Mer::Authorization.admin?(session)
                # prevent regular users from accessing
                # routes labled as "admin only"
                handle_error(Mer::ErrorMessage::UNAUTHORIZED)
            end
        else 
            if NOT_SIGNED_IN_DISALLOWED.any? { |word| path_info.include?(word) }
                # this is to ensure for routes requiring user information
                # only be access by sign-in users 
                handle_error(Mer::ErrorMessage::NEED_SIGNED)
            end

            if ADMIN_ONLY.any? { |word| path_info.include?(word) && !Mer::Authorization.admin?(session) }
                # same thing as before...
                handle_error(Mer::ErrorMessage::UNAUTHORIZED)
            end
        end
    end
end

# Runs after every request and redirects to the error page if a 404 request is 
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

# Route to handle the '/error' page.
#
get('/error') do 
    session[:action] = '/' if session[:action].nil?
    p "previous action was: #{session[:action]}"
    slim(:error)
end

# Route to handle the root page.
#
get('/') do
    redirect('/login')
end

#############
# PRE-LOGIN #
############# 

# Route to handle the '/login' page.
#
get('/login') do
    slim(:login)
end

# Route to handle the '/register' page.
#
get('/register') do
    slim(:"users/new")
end

# Route to handle the user registration form submission.
#
# @param [String] :username The username.
# @param [String] :password The password.
# @param [String] :password_confirm The password confirmation.
# @see Mer::ErrorHandler#register
# @see Mer::User#register
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
        redirect('/rooms/')
    rescue
        redirect('/error')
    end
end

# Route to handle the user login form submission.
#
# @param [String] :username The username.
# @param [String] :password The password.
# @see Mer::ErrorHandler#register
# @see Mer::User#login
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

# Route to handle the user sign out.
#
# @return [Redirect] Redirects to the root page.
get('/signout') do 
    session.clear
    redirect('/')
end

##############
# POST-LOGIN #
# -> user    #
#    -> :id  #
##############

# Route to handle viewing user profile by ID.
#
# @param [Integer] :id The user ID.
# @see Mer::ErrorHandler#register
# @see Mer::User#exists?
# @see Mer::Authorization#admin?
get('/users/:id') do 
    db = Mer::Database.new
    user_id = params[:id].to_i

    requested_user_obj = Mer::User.new(session)
    requested_user_obj.load_existing(user_id)

    if !requested_user_obj.exists?
        Mer::ErrorHandler.register(session, "User doesn't exist.")
        redirect('/error')
    end

    user_obj = Mer::User.new(session)
    user_obj.load_existing(session[:user][:id])

    @same_user = requested_user_obj.get_id == user_obj.get_id
    @admin = Mer::Authorization.admin?(session)

    @username = requested_user_obj.get_username
    @id = requested_user_obj.get_id

    slim(:"users/index")
end

# Edit user profile page
#
# @param id [Integer] the ID of the user to edit
# @see Mer::User#load_existing
get('/users/:id/edit') do 
    db = Mer::Database.new

    @user_id = params[:id].to_i
    requested_user_obj = Mer::User.new(session)
    requested_user_obj.load_existing(@user_id)

    user_obj = Mer::User.new(session)
    user_obj.load_existing(session[:user][:id])

    if @user_id == user_obj.get_id
        slim(:"users/edit")
    else
        Mer::ErrorHandler.register(session, Mer::ErrorMessage::UNAUTHORIZED)
        redirect('/error')
    end
end

# Update user profile
#
# @param id [Integer] the ID of the user to update
# @see Mer::User#load_existing
# @see Mer::User#update_username
post('/users/:id/update') do 
    db = Mer::Database.new

    @user_id = params[:id].to_i
    requested_user_obj = Mer::User.new(session)
    requested_user_obj.load_existing(@user_id)

    user_obj = Mer::User.new(session)
    user_obj.load_existing(session[:user][:id])

    if @user_id == user_obj.get_id
        requested_user_obj.update_username(params[:username])
        redirect('/')
    else
        Mer::ErrorHandler.register(session, Mer::ErrorMessage::UNAUTHORIZED)
        redirect('/error')
    end
end

##############
# POST-LOGIN #
# -> rooms   #
##############a

# Display the list of rooms
#
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

# Display the form for creating a new room
#
get('/rooms/new') do
    db = Mer::Database.new
    @tags = db.select("tags", "*")
    slim(:"rooms/new")
end

# Display the login form for joining a room
#
get('/rooms/join') do 
    slim(:"rooms/login")
end

# Create a new room
#
# @param name [String] the name of the room
# @param tags [Array<String>] the tags associated with the room
# @see Mer::Room#register
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
end

# Join a room with an invite code
#
# @param invite [String] the invite code for joining the room
# @see Mer::Room#login
post('/rooms/join') do 
    invite = params[:invite]

    room_obj = Mer::Room.new(session)
    begin
        room_obj.login(invite)
        redirect('/rooms/')
    rescue => e
        puts "UNABLE TO JOIN"
        puts e.message
        redirect('/error')
    end
end

##############
# POST-LOGIN #
# -> rooms   #
#    -> :id  #
##############

# View a room
#
# @param id [Integer] the ID of the room to display
# @see Mer::User#member_of_room?
# @see Mer::Room#load_existing
get('/rooms/:id') do 
    @room_id = params[:id].to_i
    user_obj = Mer::User.new(session)
    user_obj.load_existing(session[:user][:id])
    
    if user_obj.member_of_room?(@room_id)
        room_obj = Mer::Room.new(session)
        room_obj.load_existing(@room_id)
        @messages = room_obj.get_messages
        @invite = room_obj.get_invite
        slim(:"rooms/show")
    else
        Mer::ErrorHandler.register(session, 'Not a member.')
        redirect('/error')
    end
end

# Edit a room
#
# @param id [Integer] the ID of the room to edit
# @see Mer::User#member_of_room?
# @see Mer::User#owner_of_room?
get('/rooms/:id/edit') do 
    db = Mer::Database.new
    user_obj = Mer::User.new(session)
    user_obj.load_existing(session[:user][:id])
    @room_id = params[:id].to_i

    if user_obj.member_of_room?(@room_id) && user_obj.owner_of_room?(@room_id)
        slim(:"rooms/edit")
    else
        Mer::ErrorHandler.register(session, 'You do not have permission.')
        redirect('/error')
    end
end

# Update a room
#
# @param id [Integer] the ID of the room to update
# @param name [String] the new name of the room
# @see Mer::User#owner_of_room?
# @see Mer::Room#load_existing
# @see Mer::Room#update_name
post('/rooms/:id/update') do
    db = Mer::Database.new
    user_obj = Mer::User.new(session)
    user_obj.load_existing(session[:user][:id])
    room_id = params[:id].to_i
  
    if user_obj.owner_of_room?(room_id)
        new_name = params[:name]
        room_obj = Mer::Room.new(session)
        room_obj.load_existing(room_id)
        room_obj.update_name(new_name)
        redirect("/rooms/#{room_id}")
    else
        Mer::ErrorHandler.register(session, 'You do not have permission to update this room.')
        redirect('/error')
    end
end

# Delete a room
#
# @param id [Integer] the ID of the room to delete
# @see Mer::User#owner_of_room?
# @see Mer::Room#delete
post('/rooms/:id/delete') do 
    # check permissions
end

##############
# POST-LOGIN #
# -> message #
##############

# Create a new message in a room
#
# @param room_id [Integer] the ID of the room
# @param content [String] the content of the message
# @see Mer::Message#create
post('/message') do 
    room_id = params[:room_id].to_i
    message_content = params[:content]
    if room_id
        db = Mer::Database.new
        message_obj = Mer::Message.new(session)
        message_obj.create(message_content, room_id)
    else
        Mer::ErrorHandler.register(session, 'No room_id found.')
        redirect('/error')
    end

    redirect('/rooms/' + room_id.to_s)
end

##############
# POST-LOGIN #
# -> message #
#    -> :id  #
##############

# Delete a message
#
# @param id [Integer] the ID of the message to delete
# @see Mer::User#owner_of_message?
# @see Mer::User#owner_of_room?
# @see Mer::Message#delete
post('/message/:id/delete') do 
    message_id = params[:id].to_i
    db = Mer::Database.new

    message = db.get_equal("message", "*", "id", message_id).first
    room = db.get_equal("room", "id", "id", message['room_id']).first["id"]

    user_obj = Mer::User.new(session)
    user_obj.load_existing(session[:user][:id])

    if user_obj.owner_of_message?(message_id) || user_obj.owner_of_room?(message['room_id'])
        db.delete("message", "id", message_id)
        redirect back
    else
        Mer::ErrorHandler.register(session, Mer::ErrorMessage::UNAUTHORIZED)
        redirect('/error')
    end
end

##############
# POST-LOGIN #
# -> admin   #
##############

# Display the admin dashboard
#
get('/admin/') do 
    slim(:"admin/index")
end

# Delete all data and recreate the root user
#
# @see Mer::Database#delete
# @see Mer::Database#create_root
post('/admin/nuke') do
    # CHECK FOR ADMIN USER TYPE
    db = Mer::Database.new

    db.delete("room")
    db.delete("room_user_relation")
    db.delete("room_tags_relation")
    db.delete("message")
    db.delete("user")
    db.delete("tags")
    
    db.create_root

    redirect('/admin/')
end

##############
# POST-LOGIN #
# -> tags    #
##############

# Display the form for creating a new tag
#
get('/tags/new') do
    slim(:"tags/new")
end

# Create a new tag
#
# @param label [String] the label of the tag
# @see Mer::Tag#register
post('/tags') do 
    db = Mer::Database.new
    tag_obj = Mer::Tag.new(session)
    label = params[:label]
    begin
        tag_obj.register(label)
        redirect('/')
    rescue => e
        puts e
        redirect('/error')
    end
end