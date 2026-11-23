import Foundation

struct IdentityOptions: Equatable {
    var banners = true
    var location = true
    var domains = true
    var descriptions = true
    var serials = true
    static let none = IdentityOptions(banners:false,location:false,domains:false,descriptions:false,serials:false)
}
