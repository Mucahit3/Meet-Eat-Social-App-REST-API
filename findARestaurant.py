from geocode import getGeocodeLocation
import json
import httplib2

import sys
import codecs
sys.stdout = codecs.getwriter('utf8')(sys.stdout)
sys.stderr = codecs.getwriter('utf8')(sys.stderr)

foursquare_client_id = ""
foursquare_client_secret = ""


def findARestaurant(mealType, location):
    latitude, longitude = getGeocodeLocation(location)
    url = ('https://api.foursquare.com/v2/venues/search?client_id=%s&client_secret=%s&v=20180420&ll=%s,%s&query=%s' 
        % (foursquare_client_id, foursquare_client_secret, latitude, longitude, mealType))
    h = httplib2.Http()
    result = json.loads(h.request(url,'GET')[1])
    
    if result['response']['venues']:
        restaurant = result['response']['venues'][0]
        venue_id = restaurant['id'] 
        restaurant_name = restaurant['name']
        restaurant_address = restaurant['location']['formattedAddress']
        address = ""
        for i in restaurant_address:
            address += i + " "
        restaurant_address = address
        
        url = ('https://api.foursquare.com/v2/venues/%s/photos?client_id=%s&v=20180420&client_secret=%s' % ((venue_id, foursquare_client_id, foursquare_client_secret)))
        result = json.loads(h.request(url, 'GET')[1])

        if result['response']['photos']['items']:
            firstpic = result['response']['photos']['items'][0]
            prefix = firstpic['prefix']
            suffix = firstpic['suffix']
            imageURL = prefix + "300x300" + suffix
        else:
            imageURL = "https://upload.wikimedia.org/wikipedia/commons/4/4d/Cheeseburger.jpg"
        restaurantInfo = {'name':restaurant_name, 'address':restaurant_address, 'image':imageURL}
        print "Restaurant Name: %s" % restaurantInfo['name']
        print "Restaurant Address: %s" % restaurantInfo['address']
        print "Image: %s \n" % restaurantInfo['image']
        return restaurantInfo
    else:
        print "No Restaurants Found for %s" % location
        return "No Restaurants Found"

# if __name__ == '__main__':
#     findARestaurant("Sushi", "Istanbul,Turkey")

