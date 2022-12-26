#!/usr/bin/expect -f
# set timeout 5
# spawn ./ask-script.sh     # ask-script.sh is name of script to be run
# expect "How are you doing?\r"
# send -- "ok\r"
# expect eof


# send – to send the strings to the process
# expect – wait for the specific string from the process
# spawn – to start the command





# ===========password_change.sh=============
#!/usr/bin/expect -f
set timeout 5
set user_name [lindex $argv 0]
set pass_word [lindex $argv 1]
# spawn passwd $user_name  // or 
spawn ./expect-demo/password.sh
expect -exact "Enter new UNIX password: "
send -- "$user_name\r"
expect -exact "\rRetype new UNIX password: "
send -- "$pass_word\r"
expect eof

# ./secure-expect.sh testuser tfgh3425k