(register-services
 (make 'unknown
   #:provides '(root)
   #:start (exec-command "python3 -m http.server")
   #:respawn? #t))
