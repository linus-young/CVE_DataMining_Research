require 'net/http'

url = URI.parse('http://www.google.com')
req = Net::HTTP::Get.new(url.to_s)
res = Net::HTTP.start(url.host, url.port) {|http|
  http.request(req)
}
str = res.body
id = str.index('ChildOf')
while id != nil do
    
    id = str.index('ChildOf')
end