function render(userInput) {
  // Vulnerable: reflects untrusted input directly into the DOM.
  document.getElementById("out").innerHTML = userInput;
  document.write(userInput);
}
