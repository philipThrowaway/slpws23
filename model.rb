require "sinatra"
require "slim"
require "sqlite3"
require "bcrypt"

# The Mer module contains classes and functionality for the Mercury application.
module Mer
    # Contains constants used in the Mercury application.
    module Constants
        # The maximum length of a room name.
        MAX_ROOMNAME_LENGTH = 16
        # The maximum length of a username.
        MAX_USERNAME_LENGTH = 16
        # The maximum length of a password.
        MAX_PASSWORD_LENGTH = 32
        # The maximum length of a tag name.
        MAX_TAGNAME_LENGTH = 10
        # The maximum length of a message content.
        MAX_CONTENT_LENGTH = 200

        # Regular expression pattern to validate usernames.
        USERNAME_REGEX = /\s/
        # Regular expression pattern to validate passwords.
        PASSWORD_REGEX = /\s/
        # Regular expression pattern to validate tag names.
        TAGNAME_REGEX = /[$&+,:;=?@#|'<>.-^*()%!]/

        # The path to the database file.
        DB_PATH = 'db/database.db'.freeze
    end
    
    # Contains user types used in the Mercury application.
    module UserType
        # Represents an admin user type.
        ADMIN = 1
        # Represents a regular user type.
        USER = 0
    end

    # Contains error messages used in the Mercury application.
    module ErrorMessage
        # Error message for invalid usernames.
        USERNAME_INVALID = "The username provided was invalid. Make sure it isn't empty and is below #{Mer::Constants::MAX_USERNAME_LENGTH} characters in length. It shouldn't contain any whitespaces either.".freeze
        # Error message for invalid passwords.
        PASSWORD_INVALID = "The password provided was invalid. Make sure it isn't empty and is below #{Mer::Constants::MAX_PASSWORD_LENGTH} characters in length. It shouldn't contain any whitespaces either.".freeze
        # Error message for password mismatch.
        PASSWORD_DIFFERENT = "The passwords don't match.".freeze
        # Error message for invalid room names.
        ROOMNAME_INVALID = "The room name provided was invalid. Make sure it isn't empty and is below #{Mer::Constants::MAX_PASSWORD_LENGTH} characters in length.".freeze
        # Error message for invalid tag names.
        TAGNAME_INVALID = "The tag name provided was invalid. Make sure it isn't empty and is below #{Mer::Constants::MAX_TAGNAME_LENGTH} characters in length.".freeze
        # Error message for invalid tags.
        TAGS_INVALID = "The provided tags are invalid.".freeze
        # Error message for existing tags.
        TAG_EXISTS = 'This tag already exists.'.freeze
        # Error message for existing users.
        USER_EXISTS = "This user already exists.".freeze
        # Error message for non-existent users.
        USER_INVALID = "This user doesn't exist.".freeze
        # Error message for incorrect passwords.
        USER_WRONG_PASSWORD = "Wrong password.".freeze
        # Error message for existing entities.
        EXISTS = 'This entity already exists.'.freeze
        # Error message for already signed-in users.
        ALREADY_SIGNED = 'You are already signed in.'.freeze
        # Error message for requiring signed-in users.
        NEED_SIGNED = 'You need to be signed in.'.freeze
        # Error message for unauthorized access.
        UNAUTHORIZED = 'You are not authorized to access the attempted path.'.freeze
        # Error message for making too many requests.
        COOLDOWN = 'You have made too many requests, slow down.'.freeze
        # Error message for unknown errors.
        UNKNOWN = 'An unknown error has occurred.'.freeze
        # Error message for empty parameters.
        EMPTY = 'One of the parameters was empty.'.freeze
        # Error message for not found entities.
        NOT_FOUND = 'Not found.'.freeze
        # Error message for invalid user credentials.
        CREDENTIALS_INVALID = 'Your user credentials are invalid.'.freeze
    end

    # Contains error handling methods for the Mercury application.
    module ErrorHandler
        extend self

        # Registers an error message in the session
        #
        # @param session [Hash] the session object
        # @param error_message [String] the error message to register
        def register(session, error_message)
            puts "registering error: #{error_message}"
            session[:error] = error_message
        end

        # Raises an error and registers the error message in the session
        #
        # @param session [Hash] the session object
        # @param error_message [String] the error message to raise
        def raise_error(session, error_message)
            puts "raising error: #{error_message}"
            register(session, error_message)
            raise session[:error]
        end
    end

    # Authorization module provides methods for user authorization and access control.
    module Authorization
        extend self

        # Checks if a user is signed in
        #
        # @param session [Hash] the session object
        # @return [Boolean] true if the user is signed in, false otherwise
        def signed_in?(session)
            user_credentials = user_credentials(session)
            !user_credentials.empty? && user_exists?(user_credentials)
        end
      
        # Checks if a user is an admin
        #
        # @param session [Hash] the session object
        # @return [Boolean] true if the user is an admin, false otherwise
        def admin?(session)
            user_credentials = user_credentials(session)
            puts "USER CREDS: #{user_type(user_credentials)}"
            !user_credentials.empty? && user_exists?(user_credentials) && user_type(user_credentials) == Mer::UserType::ADMIN
        end
      
        private

        # Checks if a user exists
        #
        # @param user_credentials [Array] the user credentials
        # @return [Boolean] true if the user exists, false otherwise
        def user_exists?(user_credentials)
            db = Mer::Database.new
            puts "CHECKING THE FOLLOWING CREDENTIALS: #{user_credentials}"
            !user_credentials.empty? && !db.get_equal("user", "*", ["username", "id", "type"], user_credentials).empty?
        end

        # Retrieves the user type
        #
        # @param user_credentials [Array] the user credentials
        # @return [Integer, nil] the user type if the user exists, nil otherwise
        def user_type(user_credentials)
            db = Mer::Database.new
            user_type = db.get_equal("user", "type", ["username", "id", "type"], user_credentials).first["type"]
            user_type if !user_credentials.empty? && user_type
        end

        # Retrieves the user credentials from the session
        #
        # @param session [Hash] the session object
        # @return [Array] the user credentials [username, id, type]
        def user_credentials(session)
            user = session[:user]
            user ? [user[:username], user[:id], user[:type]] : []
        end
    end
      
    # Contains validation methods for various data in the Mercury application.
    module Validation
        extend self
    
        # Validates a username
        #
        # @param username [String] the username to validate
        # @return [Boolean] true if the username is valid, false otherwise
        def username(username)
            !(username.empty? || username.length > Mer::Constants::MAX_USERNAME_LENGTH || username.match?(Mer::Constants::USERNAME_REGEX))
        end

        # Validates a password
        #
        # @param password [String] the password to validate
        # @return [Boolean] true if the password is valid, false otherwise
        def password(password)
            !(password.empty? || password.length > Mer::Constants::MAX_PASSWORD_LENGTH || password.match?(Mer::Constants::PASSWORD_REGEX))
        end

        # Validates a room name
        #
        # @param roomname [String] the room name to validate
        # @return [Boolean] true if the room name is valid, false otherwise
        def roomname(roomname)
            !(roomname.empty? || roomname.length > Mer::Constants::MAX_ROOMNAME_LENGTH)
        end

        # Validates a tag name
        #
        # @param tagname [String] the tag name to validate
        # @return [Boolean] true if the tag name is valid, false otherwise
        def tagname(tagname)
            !(tagname.empty? || tagname.length > Mer::Constants::MAX_TAGNAME_LENGTH)
        end

        # Validates an array of tags
        #
        # @param tags [Array] the array of tags to validate
        # @return [Boolean] true if all tags are valid, false otherwise
        def tags(tags)
            puts 'validating tags...'

            if tags.nil? || tags.empty?
                return false
            end

            tags.each do |tag|
                puts "validating tag: #{tag}"
                temp = Mer::Tag.new({})
                temp.load_existing(tag.to_i)
                if !temp.exists?
                    puts 'Tag does not exist.'.freeze
                    return false
                end
            end

            return true
        end

        # Validates message content
        #
        # @param content [String] the content to validate
        # @return [Boolean] true if the content is valid, false otherwise
        def content(content)
            !(content.empty? || content.length > Mer::Constants::MAX_CONTENT_LENGTH)
        end
    end

    # Represents the Mercury application database.
    class Database
        # Initializes a new Database instance and connects to the database.
        def initialize
            puts "connecting to #{Mer::Constants::DB_PATH}..."
            @db = SQLite3::Database.new(Mer::Constants::DB_PATH)
            @db.results_as_hash = true
            puts 'connected!'.freeze
        end

        # Creates a root user in the database.
        def create_root
            session = {}
            admin_obj = Mer::User.new(session)
            begin
                admin_obj.register("admin", "admin", Mer::UserType::ADMIN)
            rescue
                # ignore
            end
        end

        # Inserts a row into the specified table.
        #
        # @param table [String] the name of the table
        # @param attributes [Array<String>] the attributes to insert
        # @param variables [Array<Object>] the values of the attributes
        def insert_into(table, attributes, variables)
            attributes = [attributes] unless attributes.is_a?(Array)
            variables = [variables] unless variables.is_a?(Array)
          
            attributes_string = attributes.join(', ')
            question_marks = (['?'] * variables.size).join(', ')
                      
            query = "INSERT INTO #{table} (#{attributes_string}) VALUES (#{question_marks})"
            puts query
            puts "variables: #{variables}"
            @db.execute(query, *variables)
        end               
    
        # Performs a SELECT query on the specified table and retrieves the specified attribute.
        #
        # @param table [String] the name of the table
        # @param attribute [String] the attribute to retrieve
        # @return [Array<Hash>] an array of hashes representing the selected rows
        def select(table, attribute)
            query = "SELECT #{attribute} FROM #{table}"
            @db.execute(query)
        end

        # Retrieves rows from the specified table where the specified attribute is equal to the target value.
        #
        # @param table [String] the name of the table
        # @param attribute [String] the attribute to retrieve
        # @param compare [String, Array<String>] the attribute(s) to compare
        # @param target [Object, Array<Object>] the target value(s) to compare against
        # @return [Array<Hash>] an array of hashes representing the selected rows
        def get_equal(table, attribute, compare, target)
            compare_fields = compare.is_a?(Array) ? compare : [compare]
            target_values = target.is_a?(Array) ? target : [target]
            
            conditions = compare_fields.map { |compare_field| "#{compare_field} = ?" }
            condition_string = conditions.join(" AND ")
            
            query = "SELECT #{attribute} FROM #{table} WHERE #{condition_string}"
            
            puts query
            puts target_values

            @db.execute(query, target_values)
        end 

        # Updates rows in the specified table where the specified attribute is equal to the target value.
        #
        # @param table [String] the name of the table
        # @param set_values [Hash] a hash representing the attribute-value pairs to update
        # @param compare [String, Array<String>] the attribute(s) to compare
        # @param target [Object, Array<Object>] the target value(s) to compare against
        def update(table, set_values, compare, target)
            set_fields = set_values.keys
            set_params = set_fields.map { |field| "#{field} = ?" }.join(", ")
            
            compare_fields = compare.is_a?(Array) ? compare : [compare]
            target_values = target.is_a?(Array) ? target : [target]
            
            conditions = compare_fields.map { |compare_field| "#{compare_field} = ?" }
            condition_string = conditions.join(" AND ")
            
            query = "UPDATE #{table} SET #{set_params} WHERE #{condition_string}"
            
            set_params_values = set_fields.map { |field| set_values[field] }
            @db.execute(query, *set_params_values, *target_values)
        end

        # Deletes rows from the specified table based on the provided conditions.
        # If no conditions are provided, all rows in the table will be deleted.
        #
        # @param table [String] the name of the table
        # @param compare [String, Array<String>, nil] the attribute(s) to compare (optional)
        # @param target [Object, Array<Object>, nil] the target value(s) to compare against (optional)
        def delete(table, compare = nil, target = nil)
            if compare.nil? && target.nil?
                query = "DELETE FROM #{table}"
                @db.execute(query)
            else
                compare_fields = compare.is_a?(Array) ? compare : [compare]
                target_values = target.is_a?(Array) ? target : [target]
        
                conditions = compare_fields.map { |compare_field| "#{compare_field} = ?" }
                condition_string = conditions.join(" AND ")
        
                query = "DELETE FROM #{table} WHERE #{condition_string}"
        
                @db.execute(query, *target_values)
            end
        end

        # Executes a custom SQL query with the provided values.
        #
        # @param string [String] the SQL query string
        # @param values [Array<Object>] the values to substitute in the query
        def execute(string, values)
            puts "Values: #{values}"
            @db.execute(string, *values)
        end
    end

    # Represents a user in the Mercury application.
    class User
        attr_reader :username
    
        # Initializes a new User instance.
        #
        # @param session [Hash] the session data for the user
        def initialize(session)
            @id = nil
            @username = nil
            @type = nil
            @session = session
        end

        # Registers a new user with the provided username, password, and type.
        #
        # @param username [String] the username for the new user
        # @param password [String] the password for the new user
        # @param type [Symbol] the type of the new user (default: `Mer::UserType::USER`)
        def register(username, password, type = Mer::UserType::USER)
            validate_credentials(username, password)

            db = Mer::Database.new
            @username = username

            unless exists?
                @type = type
                pw_digest = BCrypt::Password.create(password)
                db.insert_into("user", ["type", "username", "pw_digest"], [@type, username, pw_digest])
                @id = db.get_equal("user", "id", "username", @username).first["id"]
        
                store_user_session_data()
            else
                Mer::ErrorHandler.raise_error(@session, Mer::ErrorMessage::USER_EXISTS)
                @username = nil
            end
        end
        
        # Attempts to log in a user with the provided username and password.
        #
        # @param username [String] the username of the user
        # @param password [String] the password of the user
        def login(username, password)
            puts "attempting to log in as #{username}..."
            validate_credentials(username, password)

            db = Mer::Database.new
            @username = username

            if exists?
                user = db.get_equal("user", "*", "username", @username).first
                if BCrypt::Password.new(user["pw_digest"]) == password
                    @id = user["id"]
                    @type = user["type"]
                else
                    @username = nil
                    Mer::ErrorHandler.raise_error(@session, Mer::ErrorMessage::USER_WRONG_PASSWORD)
                end

              store_user_session_data()
              puts 'logged in!'
            else
                puts "#{@username} doesn't exist..."
                Mer::ErrorHandler.raise_error(@session, Mer::ErrorMessage::USER_INVALID)
                @username = nil
            end

            puts 'exiting...'
        end

        # Checks if the user exists in the database.
        #
        # @return [Boolean] true if the user exists, false otherwise
        def exists?
            db = Mer::Database.new
            !db.get_equal("user", "username", "username", @username).empty?
        end

        # Checks if the user is a member of the specified room.
        #
        # @param room_id [Integer] the ID of the room
        # @return [Boolean] true if the user is a member of the room, false otherwise
        def member_of_room?(room_id)
            db = Mer::Database.new
            !db.get_equal("room_user_relation", "1", ["room_id", "user_id"], [room_id, @id]).first.nil?
        end

        # Checks if the user is the owner of the specified room.
        #
        # @param room_id [Integer] the ID of the room
        # @return [Boolean] true if the user is the owner of the room, false otherwise
        def owner_of_room?(room_id)
            db = Mer::Database.new
            !db.get_equal("room", "1", ["id", "owner_id"], [room_id, @id]).first.nil?
        end

        # Checks if the user is the owner of the specified message.
        #
        # @param message_id [Integer] the ID of the message
        # @return [Boolean] true if the user is the owner of the message, false otherwise
        def owner_of_message?(message_id)
            db = Mer::Database.new
            !db.get_equal("message", "1", ["id", "owner_id"], [message_id, @id]).first.nil?
        end

        # Adds the user to the specified room.
        #
        # @param room_id [Integer] the ID of the room to join
        def join_room(room_id)
            db = Mer::Database.new
            db.insert_into("room_user_relation", ["room_id", "user_id"], [room_id, @id])
        end

        # Returns the ID of the user.
        #
        # @return [Integer] the ID of the user
        def get_id()
            @id
        end

        # Returns the username of the user.
        #
        # @return [String] the username of the user
        def get_username()
            @username
        end

        # Updates the username of the user.
        #
        # @param username [String] the new username
        def update_username(username)
            unless Mer::Validation.username(username)
                Mer::ErrorHandler.raise_error(@session, Mer::ErrorMessage::USERNAME_INVALID)
            end

            @username = username
            db = Mer::Database.new
            db.update("user", { username: @username }, "id", @id)
        end

        # Loads an existing user with the specified ID from the database.
        #
        # @param id [Integer] the ID of the existing user to load
        def load_existing(id)
            db = Mer::Database.new
            @id = id
            @username = db.get_equal("user", "username", "id", @id).first["username"]
            @type = db.get_equal("user", "type", "id", @id).first["type"]
        end
        
        private

        # Validates the username and password credentials.
        #
        # @param username [String] the username to validate
        # @param password [String] the password to validate
        def validate_credentials(username, password)
            unless Mer::Validation.username(username)
                Mer::ErrorHandler.raise_error(@session, Mer::ErrorMessage::USERNAME_INVALID)
            end

            unless Mer::Validation.password(password)
                Mer::ErrorHandler.raise_error(@session, Mer::ErrorMessage::PASSWORD_INVALID)
            end
        end
        
        # Stores user session data in the session hash.
        def store_user_session_data
            @session[:user] = {
                username: @username,
                id: @id,
                type: @type
            }

            puts "current user id: #{@session[:user][:id]}"
        end
    end

    # Represents a room in the Mercury application.
    class Room
        attr_reader :roomname
    
        # Initializes a new instance of the Room class.
        #
        # @param session [Session] the session object
        def initialize(session)
            @id = nil
            @roomname = nil
            @invite = nil
            @owner_id = nil
            @tags = nil
            @session = session
        end
    
        # Registers a new room.
        #
        # @param roomname [String] the name of the room
        # @param tags [Array<Integer>] an array of tag IDs associated with the room
        def register(roomname, tags)
            validate_credentials(roomname, tags)

            db = Mer::Database.new
            @roomname = roomname
            @owner_id = @session[:user][:id]

            @invite = unique_invite()
            db.insert_into("room", ["name", "invite", "owner_id"], [@roomname, @invite, @owner_id])
            @id = db.get_equal("room", "id", "invite", @invite).first["id"]

            tags.each do |tag|
                tag = tag.to_i
                puts tag
                db.insert_into("room_tags_relation", ["room_id", "tag_id"], [@id, tag])
                puts "after tag"
            end
            puts "before reg"
            db.insert_into("room_user_relation", ["room_id", "user_id"], [@id, @owner_id])
            puts "after reg"
        end

        # Logs into an existing room.
        #
        # @param invite [String] the invite code of the room
        def login(invite)
            db = Mer::Database.new
            id = db.get_equal("room", "id", "invite", invite).first

            if id.nil?
                puts "id is nil"
                Mer::ErrorHandler.raise_error(@session, "Room doesn't exist.")
            end

            id = id["id"]

            user_obj = Mer::User.new(@session)
            user_obj.load_existing(@session[:user][:id])

            if !user_obj.member_of_room?(id)
                user_obj.join_room(id)
            end
        end

        # Retrieves messages for the room.
        #
        # @return [Array<Hash>] an array of message hashes containing message details
        def get_messages
            db = Mer::Database.new
            return db.execute("
                SELECT m.id AS message_id, m.room_id AS message_room_id, m.content AS message_content, m.owner_id AS message_owner, u.username AS message_owner_username
                FROM message AS m
                JOIN user AS u ON u.id = m.owner_id
                WHERE m.room_id = ?
                ", @id)
        end

        # Updates the name of the room.
        #
        # @param roomname [String] the new room name
        def update_name(roomname)
            unless Mer::Validation.username(roomname)
                Mer::ErrorHandler.raise_error(@session, Mer::ErrorMessage::ROOMNAME_INVALID)
            end

            @roomname = roomname
            db = Mer::Database.new
            db.update("room", { name: @roomname }, "id", @id)
        end

        # Loads an existing room with the specified ID from the database.
        #
        # @param id [Integer] the ID of the existing room to load
        def load_existing(id)
            db = Mer::Database.new
            @id = id
            @roomname = db.get_equal("room", "name", "id", @id).first["name"]
            @invite = db.get_equal("room", "invite", "id", @id).first["invite"]
        end

        # Retrieves the invite code of the room.
        #
        # @return [String] the invite code of the room
        def get_invite
            return @invite
        end

        private

        # Generates a unique invite code for the room.
        #
        # @return [String] a unique invite code
        def unique_invite
            db = Mer::Database.new
            invite = (0...8).map { (65 + rand(26)).chr }.join
            existing_room = db.get_equal("room", "*", "invite", invite).empty?
            if db.get_equal("room", "*", "invite", invite).empty?
                return invite
            else
                unique_invite()
            end
        end

        # Validates the credentials for registering a room.
        #
        # @param roomname [String] the name of the room
        # @param tags [Array<Integer>] an array of tag IDs associated with the room
        # @raise [Mer::Error] if the roomname or tags are invalid
        def validate_credentials(roomname, tags)
            puts 'validating room credentials...'
            
            unless Mer::Validation.roomname(roomname)
                Mer::ErrorHandler.raise_error(@session, Mer::ErrorMessage::ROOMNAME_INVALID)
            end
          
            unless Mer::Validation.tags(tags)
                Mer::ErrorHandler.raise_error(@session, Mer::ErrorMessage::TAGS_INVALID)
            end
        end
    end

    # Represents a tag associated with a room.
    class Tag
        attr_reader :tagname

        # Initializes a new instance of the Tag class.
        #
        # @param session [Session] the session object associated with the tag
        def initialize(session)
            @id = nil
            @tagname = nil
            @session = session
        end

        # Registers a new tag with the specified tag name.
        #
        # @param tagname [String] the name of the tag to register
        # @raise [Mer::Error] if the tagname is invalid or already exists
        def register(tagname)
            validate_credentials(tagname)

            db = Mer::Database.new
            @tagname = tagname

            if !exists?
                db.insert_into("tags", "label", @tagname)
                # INSERT INTO #{table} (#{attributes_string}) VALUES (#{question_marks})
                # dbh.insert_into("tags", "label", @tagname)
                @id = db.get_equal("tags", "id", "label", @tagname).first["id"]
            else
                Mer::ErrorHandler.raise_error(@session, Mer::ErrorMessage::TAG_EXISTS)
                @tagname = nil
            end
        end

        # Loads an existing tag with the specified ID.
        #
        # @param id [Integer] the ID of the tag to load
        def load_existing(id)
            puts "loading tag: #{id}"
            db = Mer::Database.new
            @id = id
            @tagname = db.get_equal("tags", "label", "id", @id).first["label"]
        end

        # Checks if the tag already exists.
        #
        # @return [Boolean] true if the tag exists, false otherwise
        def exists?
            puts 'checking if a tag exists...'
            db = Mer::Database.new
            return !db.get_equal("tags", "id", "id", @id).empty? if @id
            return !db.get_equal("tags", "label", "label", @tagname).empty? if @tagname
        end

        private

        # Validates the credentials for registering a tag.
        #
        # @param tagname [String] the name of the tag
        # @raise [Mer::Error] if the tagname is invalid
        def validate_credentials(tagname)
            unless Mer::Validation.tagname(tagname)
                Mer::ErrorHandler.raise_error(@session, Mer::ErrorMessage::TAGNAME_INVALID)
            end
        end
    end

    # Represents a message associated with a room.
    class Message  
        # Initializes a new instance of the Message class.
        #
        # @param session [Session] the session object associated with the message  
        def initialize(session)
            @id = nil
            @content = nil
            @room_id = nil
            @owner_id = nil
            @session = session
        end

        # Creates a new message with the specified content in the specified room.
        #
        # @param content [String] the content of the message
        # @param room_id [Integer] the ID of the room to post the message in
        # @raise [Mer::Error] if the content is invalid or the user is not a member of the room
        def create(content, room_id)
            db = Mer::Database.new
            validate_credentials(content)
            user_obj = Mer::User.new(@session)
            user_obj.load_existing(@session[:user][:id])

            if user_obj.member_of_room?(room_id)
                @content = content
                @room_id = room_id
                @owner_id = @session[:user][:id]

                db.insert_into("message", ["content", "room_id", "owner_id"], [@content, @room_id, @owner_id])
            else 
                # error
            end
        end

        private

        # Validates the credentials for creating a message.
        #
        # @param content [String] the content of the message
        # @raise [Mer::Error] if the content is invalid
        def validate_credentials(content)
            unless Mer::Validation.content(content)
                Mer::ErrorHandler.raise_error(@session, 'Error with message content.')
            end
        end
    end
end