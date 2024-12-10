const prevButton = document.querySelector('.prev');
const nextButton = document.querySelector('.next');
const carousel = document.querySelector('.carousel');

prevButton.addEventListener('click', () => {
  carousel.scrollBy({
    left: -carousel.offsetWidth,
    behavior: 'smooth'
  });
});

nextButton.addEventListener('click', () => {
  carousel.scrollBy({
    left: carousel.offsetWidth,
    behavior: 'smooth'
  });
});