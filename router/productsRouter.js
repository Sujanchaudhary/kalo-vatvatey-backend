const router = require("express").Router();
const productController = require("./../controller/productController");

const authController = require('./../controller/authController')
const reviewController = require("./../controller/reviewController");
const dashboardController = require("../controller/dashboardController");

const {
    multer,
    storage
} = require("./../servces/multer");

const upload = multer({
    storage: storage
});

router.get("/show_products",
    // authController.isLoggedIn,
    productController.show_products
);

// need to change method into POST
router.get("/show_products/filter",
    productController.show_filter_product
   
);

router.get("/show_one_product/:slug",
    productController.showone
);

router.patch("/sold/:id",
    authController.isLoggedIn,
    authController.givePermissionTo("seller"),
    productController.checkSold // update the item as sold
);

router.post("/create_products",
    authController.isLoggedIn,
    // authController.givePermissionTo("seller"),
    upload.array("photo", 5),
    productController.create_product
);


router.patch("/update_product/:id",
    authController.isLoggedIn,
    authController.givePermissionTo("seller"),
    productController.update_products
);

router.delete("/delete_product/:id",
    authController.isLoggedIn,
    authController.givePermissionTo("seller"),
    productController.delete_products
);


// review
router.post("/:id/review",
    authController.isLoggedIn,
    authController.givePermissionTo("user"),
    reviewController.review_upload
);

router.delete("/:id/review/delete",
    authController.isLoggedIn,
    authController.givePermissionTo("user"),
    reviewController.deleteReview
);

router.patch("/:id/review/update",
    authController.isLoggedIn,
    authController.givePermissionTo("user"),
    reviewController.updateReview
);


// add to cart
// router.post("/addtocart/:productId",
//     authController.isLoggedIn,
//     authController.givePermissionTo("user"),
//     productController.addToCart
// );


// // add to favourite 
// router.post("/favourite/:productId",
//     authController.isLoggedIn,
//     authController.givePermissionTo("user"),
//     productController.AddToFavourites
// )


// dashboard / tracker seller
router.get("/dashboard/uploads",
    // authController.isLoggedIn,
    // authController.givePermissionTo("seller"),
    dashboardController.viewUploads
);


// Search endpoint
router.get("/search/:key", productController.searchProducts)


module.exports = router;