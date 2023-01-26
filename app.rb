require 'sinatra'
require 'sinatra/reloader'
require 'slim'
require 'bcrypt'

require_relative 'lib/helpers.rb'

enable :sessions
DB_PATH ||= 'db/database.db'

def is_authenticated?()
    id = session[:id].to_i
    if id then true else false end
end

def auth_gate()
    if not is_authenticated?()
        redirect('/')
    end 
end

get('/') do
    if is_authenticated?() # check if user hasn't logged in
        redirect('/login')
    else
        redirect('/rooms')
    end
end

get('/login') do
    slim(:login)
end

post('/login') do 
    "success"
end

get('/register') do
    slim(:"users/new")
end

post('/users/') do
    db = Database::connect(DB_PATH)
end

get('/rooms') do
    db = Database::connect(DB_PATH)
end