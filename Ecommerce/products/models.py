from django.db import models

# Create your models here.  
class Product(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2 ,)
    stock_quantity = models.IntegerField(default=0)
    image = models.ImageField(upload_to='products/imgs/')
    sold_quantity = models.IntegerField(default=0)
    category = models.ForeignKey('Category', on_delete=models.CASCADE)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    discounted_price = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    #colors,size,brand,fav,rev,rat
    


    def __str__(self):
        return self.name
    
class Category(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField()

    def __str__(self):
        return self.name




