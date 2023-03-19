/**
 * JavaScript Sample
 */

$(function () {
  if(window.ComponentsKlickpagesHeaderBinded){
    return false;
  }

  window.ComponentsKlickpagesHeaderBinded = true;

  $(".navicon").click(function(){
    $(this).toggleClass("open").parents('.header-container').find('.header-navigation').slideToggle(400);
  });
});
