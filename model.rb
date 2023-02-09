require 'sqlite3'

module Database
    def self.connect(path)
        p "connecting to #{@path}"
        db = SQLite3::Database.new(path)
        db.results_as_hash = true
        return db
    end
end

module Auth
    def self.init(session)
        @session = session
    end

    def self.is_authenticated?()
        if @session[:id] then true else false end
    end

    def self.redirect(url)
        
    end
end