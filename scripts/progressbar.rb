
def progress(now, max)
    now = now + 1
    print ("\r[ #{(now * 100.0 / max).round(2)}% ] ")
    (60 * now / max).times do
        print ('=')
    end
    print now == max ? '[FINISHED]' : '> '
end