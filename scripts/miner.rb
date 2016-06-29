require_relative 'cwe_tree_mine.rb'
require_relative 'progressbar.rb'

min = 1
max = 1003
exceptions = [604, 630]

total = open('statistics/CWE_structure.csv', 'w')
total.write('id,description,children,parents')
total.write("\n")

for i in min..max do
    next if exceptions.include?(i)
    node = get_cwe_info("http://0.0.0.0:8000/#{i}.json")
    next if node == false

    filename = "rawdata/cwe/#{i}.json"
    target = open(filename, 'w')
    target.write(node.to_json)
    
    total.write(node.to_s)
    total.write("\n")

    progress(i, max)
    target.close
end

total.close

puts