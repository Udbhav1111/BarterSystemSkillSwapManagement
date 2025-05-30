function scrollSkills(direction) {
    const container = document.querySelector('.scroll-container');
    container.scrollBy({ left: direction * 300, behavior: 'smooth' });
}

document.addEventListener("DOMContentLoaded", function() {
    let previewVideo = document.getElementById("preview-video");

    if (previewVideo) {
        if (!localStorage.getItem("previewWatched")) {
            previewVideo.play();
            setTimeout(() => {
                previewVideo.pause();
                localStorage.setItem("previewWatched", "true");
            }, 5000); // ✅ Plays only once per session
        }
    }
});

//LOGOUT API CALL WHEN SOMEONE CLICK ON LOGOUT
function logoutUser() {
    fetch('/api/logout', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    })
    .then(response => response.json())
    .then(data => {
        alert(data.message);
        window.location.href = "/"; // Redirect to home after logout
    })
    .catch(error => console.error("Error logging out:", error));
}

