require 'net/http'

url = URI.parse('http://cwe.mitre.org/data/definitions/2.html')
req = Net::HTTP::Get.new(url.to_s)
res = Net::HTTP.start(url.host, url.port) {|http|
  http.request(req)
}
str = res.body
puts str
# id = str.index('ChildOf')
# while id != nil do
    
#     id = str.index('ChildOf')
# end