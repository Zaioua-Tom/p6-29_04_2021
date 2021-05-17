const express = require('express');
const router = express.Router();

const auth = require('../middleware/auth');
const multer = require('../middleware/multer-config');

const sauceCtrl = require('../controllers/sauces');


router.post('/', auth, multer, sauceCtrl.createSauce);
router.get('/:id', auth, sauceCtrl.getOneSauce);
router.put('/:id', auth, multer, sauceCtrl.modifySauce);
//router.post('/:id/like', auth, sauceCtrl.likeSauce);
//router.post('/:id/dislike', auth, sauceCtrl.dislikeSauce);
router.delete('/:id', auth, sauceCtrl.deleteSauce);
router.get('/', auth, sauceCtrl.getAllSauces);
router.post('/:id/like', auth, sauceCtrl.likeDislike);

module.exports = router;