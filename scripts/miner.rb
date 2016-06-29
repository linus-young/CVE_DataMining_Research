require_relative 'cwe_tree_mine.rb'
require_relative 'progressbar.rb'

min = 1
max = 1003
exceptions = [604, 630]

for i in min..max do
    next if exceptions.include?(i)
    node = get_cwe_info("http://localhost:5000/#{i}.html")
    if node == false 
        next
    end
    filename = "rawdata/cwe/#{i}.json"
    target = open(filename, 'w')
    target.write(node)
    progress(i, max)
    target.close
end

puts