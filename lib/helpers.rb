require 'sqlite3'
module Database
    def self.connect(path)
        p "connecting to #{@path}"
        db = SQLite3::Database.new(path)
        db.results_as_hash = true
        return db
    end
end