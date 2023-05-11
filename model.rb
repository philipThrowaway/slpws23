require "sinatra"
require "slim"
require "sqlite3"
require "bcrypt"

module Mer
    module Constants
        MAX_ROOMNAME_LENGTH = 16
        MAX_USERNAME_LENGTH = 16
        MAX_PASSWORD_LENGTH = 32
        MAX_TAGNAME_LENGTH = 10

        USERNAME_REGEX = /\s/
        PASSWORD_REGEX = /\s/
        TAGNAME_REGEX = /[$&+,:;=?@#|'<>.-^*()%!]/

        DB_PATH = 'db/database.db'.freeze
    end
    
    module UserType
        ADMIN = 1
        USER = 0
    end

    module ErrorMessage
        USERNAME_INVALID = "The username provided was invalid. Make sure it isn't empty and is below #{Mer::Constants::MAX_USERNAME_LENGTH} characters in length. It shouldn't contain any whitespaces either.".freeze
        PASSWORD_INVALID = "The password provided was invalid. Make sure it isn't empty and is below #{Mer::Constants::MAX_PASSWORD_LENGTH} characters in length. It shouldn't contain any whitespaces either.".freeze
        PASSWORD_DIFFERENT = "The passwords don't match.".freeze
        ROOMNAME_INVALID = "The room name provided was invalid. Make sure it isn't empty and is below #{Mer::Constants::MAX_PASSWORD_LENGTH} characters in length.".freeze
        TAGS_INVALID = "The provided tags are invalid.".freeze
        TAG_EXISTS = 'This tag already exists.'.freeze
        USER_EXISTS = "This user already exists.".freeze
        USER_INVALID = "This user doesn't exist.".freeze
        USER_WRONG_PASSWORD = "Wrong password.".freeze
        EXISTS = 'This entity already exists.'.freeze
        ALREADY_SIGNED = 'You are already signed in.'.freeze
        NEED_SIGNED = 'You need to be signed in.'.freeze
        UNAUTHORIZED = 'You are not authorized to access the attempted path.'.freeze
        COOLDOWN = 'You have made too many requests, slow down.'.freeze
        UNKNOWN = 'An unknown error has occurred.'.freeze
        EMPTY = 'One of the parameters was empty.'.freeze
        NOT_FOUND = 'Not found.'.freeze
        CREDENTIALS_INVALID = 'Your user credentials are invalid.'.freeze
    end

    module ErrorHandler
        extend self
    
        def register(session, error_message)
            puts "registering error: #{error_message}"
            session[:error] = error_message
        end

        def raise_error(session, error_message)
            puts "raising error: #{error_message}"
            register(session, error_message)
            raise session[:error]
        end
    end

    module Authorization
        extend self

        def valid?(session)
            user_credentials = user_credentials(session)
            user_exists?(user_credentials)
        end
      
        def signed_in?(session)
            user_credentials = user_credentials(session)
            !user_credentials.empty? && user_exists?(user_credentials)
        end
      
        def admin?(session)
            user_credentials = user_credentials(session)
            !user_credentials.empty? && user_exists?(user_credentials) && user_type(user_credentials) == Mer::UserType::ADMIN
        end
      
        private
      
        def user_exists?(user_credentials)
            db = Mer::Database.new
            puts "CHECKING THE FOLLOWING CREDENTIALS: #{user_credentials}"
            !user_credentials.empty? && !db.get_equal("user", "*", ["username", "id", "type"], user_credentials).empty?
        end
      
        def user_type(user_credentials)
            db = Mer::Database.new
            user_type = db.get_equal("user", "type", ["username", "id", "type"], user_credentials).first
            user_type if !user_credentials.empty? && user_type
        end
      
        def user_credentials(session)
            user = session[:user]
            user ? [user[:username], user[:id], user[:type]] : []
        end
    end
      

    module Validation
        extend self
    
        def username(username)
            !(username.empty? || username.length > Mer::Constants::MAX_USERNAME_LENGTH || username.match?(Mer::Constants::USERNAME_REGEX))
        end
    
        def password(password)
            !(password.empty? || password.length > Mer::Constants::MAX_PASSWORD_LENGTH || password.match?(Mer::Constants::PASSWORD_REGEX))
        end

        def roomname(roomname)
            !(roomname.empty? || roomname.length > Mer::Constants::MAX_ROOMNAME_LENGTH)
        end

        def tagname(tagname)
            !(tagname.empty? || tagname.length > Mer::Constants::MAX_TAGNAME_LENGTH || tagname.match?(Mer::Constants::TAGNAME_REGEX))
        end

        def tags(tags)
            puts 'validating tags...'

            if tags.empty?
                return false
            end

            tags.each do |tag|
                puts "validating tag: #{tag}"
                temp = Mer::Tag.new
                temp.load_existing(tag.to_i)
                if !temp.exists?
                    puts 'Tag does not exist.'.freeze
                    return false
                end
            end

            return true
        end

        private

    end

    class Database
        def initialize
            puts "connecting to #{Mer::Constants::DB_PATH}..."
            @db = SQLite3::Database.new(Mer::Constants::DB_PATH)
            @db.results_as_hash = true
            puts 'connected!'.freeze
        end
    
        def insert_into(table, attributes, variables)
            attributes_string = attributes.join(', ')
            question_marks = (['?'] * variables.size).join(', ')
            
            query = "INSERT INTO #{table} (#{attributes_string}) VALUES (#{question_marks})"
            puts query
            puts "variables: #{variables}"
            @db.execute(query, *variables)
        end          
    
        def select(table, attribute)
            query = "SELECT #{attribute} FROM #{table}"
            @db.execute(query)
        end

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

        def execute(string, values)
            puts "Values: #{values}"
            @db.execute(string, *values)
        end
    end

    class User
        attr_reader :username
    
        def initialize(session)
            @id = nil
            @username = nil
            @type = nil
            @session = session
        end
    
        def register(username, password, type = Mer::UserType::USER)
            validate_credentials(username, password)

            db = Mer::Database.new
            @username = username

            unless exists?
                @type = type
                pw_digest = BCrypt::Password.create(password)
                db.insert_into("user", ["type", "username", "pw_digest"], [Mer::UserType::ADMIN, username, pw_digest])
                @id = db.get_equal("user", "id", "username", @username).first
        
                store_user_session_data()
            else
                Mer::ErrorHandler.raise_error(@session, Mer::ErrorMessage::USER_EXISTS)
                @username = nil
            end
        end
        
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
    
        def exists?
            db = Mer::Database.new
            !db.get_equal("user", "username", "username", @username).empty?
        end
    
        private
    
        def validate_credentials(username, password)
            unless Mer::Validation.username(username)
                Mer::ErrorHandler.raise_error(@session, Mer::ErrorMessage::USERNAME_INVALID)
            end

            unless Mer::Validation.password(password)
                Mer::ErrorHandler.raise_error(@session, Mer::ErrorMessage::PASSWORD_INVALID)
            end
        end
    
        def store_user_session_data
            @session[:user] = {
                username: @username,
                id: @id,
                type: @type
            }

            puts "current user id: #{@session[:user][:id]}"
        end
    end

    class Room
        attr_reader :roomname
    
        def initialize(session)
            @id = nil
            @roomname = nil
            @invite = nil
            @owner_id = nil
            @tags = nil
            @session = session
        end
    
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
        
        def login(invite)
            db = Mer::Database.new
            id = db.get_equal("room", "id", "invite", invite).first["id"]
            
            if id.empty?
                # display error morron
            end

            # make this a function for the user class
            if db.get_equal("room_user_relation", ["room_id", "user_id"], [id, session[:user][:id]]).empty?
                db.insert_into("room_user_relation", ["room_id", "user_id"], [id, session[:user][:id]])
            end
        end
    
        private
    
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

    class Tag
        attr_reader :tagname
    
        def initialize
            @id = nil
            @tagname = nil
        end

        def register(tagname)
            validate_credentials(tagname)

            db = Mer::Database.new
            @tagname = tagname

            if !exists?
                db.insert_into("tags", "label", @tagname)
                @id = db.get_equal("tags", "id", "label", @tagname).first
            else
                Mer::ErrorHandler.raise_error(@session, Mer::ErrorMessage::TAG_EXISTS)
                @tagname = nil
            end
        end

        def load_existing(id)
            puts "loading tag: #{id}"
            db = Mer::Database.new
            @id = id
            @tagname = db.get_equal("tags", "label", "id", @id).first
        end

        def exists?
            return false if @tagname.nil? || @id.nil?
        
            puts 'checking if a tag exists...'
            db = Mer::Database.new
            return !db.get_equal("tags", "id", "id", @id).empty? if @id
            return !db.get_equal("tags", "label", "label", @tagname).empty? if @tagname
        end

        private

        def validate_credentials(tagname)
            unless Mer::Validation.tagname(tagname)
                Mer::ErrorHandler.raise_error(@session, Mer::ErrorMessage::ROOMNAME_INVALID)
            end
        end
    end
end

module Mercury
    module Rules
        MAX_NAME_LENGTH = 16
    end

    module UserType
        ADMIN = 1
        USER = 0
    end

    module ErrorMessage
        EXISTS = 'This entity already exists.'
        UNAUTHORIZED = 'You are not authorized to access the attempted path.'
        COOLDOWN = 'You have made too many requests, slow down.'
        UNKNOWN = 'An unknown error has occured.'
    end

    class ErrorHandler
        def initialize
            @previous_request = '/'
            @error_message = Mercury::ErrorMessage::UNKNOWN
        end

        def display(error_message: Mercury::ErrorMessage::UNKNOWN)
            slim(:"error", locals: { error_message: error_message.to_s, previous_request: request.path_info })
        end
    end

    @error = Mercury::ErrorHandler.new()

    class Database
        def initialize(path)
            @db = SQLite3::Database.new(path)
            @db.results_as_hash = true
        end

        class Room
            def initialize
                @owner_id = nil
                @name = nil
                @invite = nil
                @tags = nil
            end

            def generate_invite
                invite = (0...8).map { (65 + rand(26)).chr }.join
                if self.exists_invite?(invite)
                    self.generate_invite()
                end

                return invite
            end

            def exists_invite?(invite)
                !@db.execute("SELECT invite FROM room WHERE invite = ?", invite).empty?
            end

            def create(owner_id, name, tags)
                @name = name
                if !self.exists?
                    @owner_id = owner_id
                    @invite = self.generate_invite()
                    @tags = tags
                    @db.execute("INSERT INTO room(name, invite, owner_id) VALUES(?, ?, ?)", @name, @invite, @owner)

                else
                    @error.display(Mercury::ErrorMessage::EXISTS)
                end
            end

            def exists?
                !@db.execute("SELECT name FROM room WHERE name = ?", @name).empty?
            end
        end

        class Tag

        end

        class User
            def initialize
                @username = nil
                @type = nil
            end
            
            def create_root
                p 'attempting to create root user...'
                @username = "admin"
                password = "admin"
                if !self.exists?
                    p 'success!'
                    @type = type
                    pw_digest = BCrypt::Password.create(password)
                    @db.execute("INSERT INTO users(type, username, pw_digest) VALUES(?, ?, ?)", Mercury::UserType::ADMIN, username, pw_digest)
                end
            end

            def create(type: Mercury::UserType, username: String, password: String)
                @username = username
                if !self.exists?
                    @type = type
                    pw_digest = BCrypt::Password.create(password)
                    @db.execute("INSERT INTO users(type, username, pw_digest) VALUES(?, ?, ?)", type, username, pw_digest)
                else
                    @error.display(Mercury::ErrorMessage::EXISTS)
                end
            end

            def find(id)
                results = @db.execute("SELECT * FROM users WHERE id = ?", id).first

            end

            def exists?
                !@db.execute("SELECT username FROM users WHERE username = ?", @username).empty?
            end 

            def admin?
                ""
            end
        end
    end
end