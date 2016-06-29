require 'json'

class CweNode 
    attr_accessor :id;
    attr_accessor :name;
    attr_accessor :children;
    attr_accessor :parents;

    def to_json
        a = {'id'         => @id, 
         'name'       => @name,
         'children'   => @children,
         'parents'    => @parents
        }
        JSON.generate a
    end

end