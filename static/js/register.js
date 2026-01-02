document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('registrationForm');
    const messageArea = document.getElementById('messageArea');

    form.addEventListener('submit', async (event) => {
        // Prevent the default form submission which reloads the page
        event.preventDefault();

        // Clear previous messages
        messageArea.textContent = '';
        messageArea.className = 'message-area';

        // Get data from the form
        const formData = new FormData(form);
        const data = Object.fromEntries(formData.entries());

        try {
            const response = await fetch('/api/rest/users/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data),
            });

            const result = await response.json();

            if (response.ok) {
                // Handle success
                messageArea.textContent = `User '${result.username}' registered successfully! You can now log in.`;
                messageArea.classList.add('success');
                form.reset(); // Clear the form fields
            } else {
                // Handle errors from the API (e.g., username already exists)
                messageArea.textContent = `Error: ${result.detail}`;
                messageArea.classList.add('error');
            }
        } catch (error) {
            // Handle network errors
            messageArea.textContent = 'A network error occurred. Please try again later.';
            messageArea.classList.add('error');
            console.error('Registration failed:', error);
        }
    });
});
