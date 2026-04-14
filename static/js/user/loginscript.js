document.getElementById("togglePassword").addEventListener("click", function() {
  var passwordInput = document.getElementById("password");
  if (passwordInput.type === "password") {
    passwordInput.type = "text";
    this.classList.replace("bx-show", "bx-hide");
  } else {
    passwordInput.type = "password";
    this.classList.replace("bx-hide", "bx-show");
  }
});