require 'net/http'
require_relative 'cwe_node.rb'

def get_cwe_info(url_str)
  node = CweNode.new;

  url = URI.parse(url_str)
  req = Net::HTTP::Get.new(url.to_s)
  res = Net::HTTP.start(url.host, url.port) {|http|
    http.request(req)
  }
  is_depre = res.body.index(/DEPRECATED/)
  return false if is_depre
  is_view  = res.body.index(/View ID:/)
  return false if is_view

  id_str = res.body.scan(/<h2 style="display:inline; margin:0px 0px 2px 0px; vertical-align: text-bottom">CWE-([0-9]+): ([^<^>]+)<\/h2>/).flatten

  node.id = id_str[0].to_i
  node.name = id_str[1].to_s

  if node.id == 0 
    return false
  end

  a = res.body.scan(/>([A-Za-z0-9\-: ]+)</).flatten

  until a.size() > 0 && (a[0] == 'ChildOf' || a[0] == 'ParentOf' || a[0] == 'MemberOf') do
    a.delete_at(0);
  end

  if a.size() < 1 
    return false
  end

  node.parents    = Array.new
  node.children   = Array.new

  i = 0
  while i < a.size do 
    case a[i] 
    when 'ChildOf' 
      node.parents.push(a[i + 2].to_i)
    when 'ParentOf'
      node.children.push(a[i + 2].to_i)
    end
    i = i + 1
  end

  node
end