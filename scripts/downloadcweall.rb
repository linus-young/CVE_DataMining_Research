require_relative 'progressbar.rb'
require 'net/http'

min = 1
max = 1003

for i in min..max do
  filename = "rawdata/cwe/html/#{i}.json"
  url = URI.parse("http://cwe.mitre.org/data/definitions/#{i}.html")
  req = Net::HTTP::Get.new(url.to_s)
  res = Net::HTTP.start(url.host, url.port) {|http|
    http.request(req)
  }
  target = open(filename, 'w')
  target.write(res.body)
  progress(i, max)
  target.close
end