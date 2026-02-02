internal import Foundation

protocol CFCastable {
    static var cfTypeID: CFTypeID { get }
}

extension Any? {
    func cast<T: CFCastable>(as type: T.Type = T.self) -> T? {
        // Note that Any can always be cast to AnyObject even for value types like Int.
        // Swift will automatically convert Swift value types like Int to ObjC types like NSNumber.
        guard let self, CFGetTypeID(self as AnyObject) == type.cfTypeID else {
            return nil
        }
        return (self as! T)
    }
}

func cast<T: CFCastable>(_ value: AnyObject, as type: T.Type = T.self) -> T? {
    guard CFGetTypeID(value) == type.cfTypeID else {
        return nil
    }
    return (value as! T)
}

extension CFString: CFCastable {
    static let cfTypeID = CFStringGetTypeID()
}

extension CFNumber: CFCastable {
    static let cfTypeID = CFNumberGetTypeID()
}

extension CFBoolean: CFCastable {
    static let cfTypeID = CFBooleanGetTypeID()
}

extension CFData: CFCastable {
    static let cfTypeID = CFDataGetTypeID()
}

extension CFDate: CFCastable {
    static let cfTypeID = CFDateGetTypeID()
}

extension CFDictionary: CFCastable {
    static let cfTypeID = CFDictionaryGetTypeID()
}

extension CFArray: CFCastable {
    static let cfTypeID = CFArrayGetTypeID()
}

extension CFSet: CFCastable {
    static let cfTypeID = CFSetGetTypeID()
}
