gtn.log("Welcome to GuessTheNumber LiveOps!")
gtn.log("LiveOps signing and download test passed.")

return {
    title = "Welcome to LiveOps",
    description = "A quick check that verified LiveOps content is running.",
    prompt = "What verifies this remote activity before it runs?",
    options = { "The signed bundle", "The filename alone" },
    correct_option = 1,
    success_message = "Correct! The signed bundle was verified before this activity ran.",
    failure_message = "Not quite. The app verifies the signed bundle before running this activity."
}
