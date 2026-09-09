package com.ngoline.easygpg.ui.encrypt

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.Spinner
import android.widget.Toast
import androidx.fragment.app.Fragment
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.lifecycleScope
import androidx.preference.PreferenceManager
import com.ngoline.easygpg.data.encryptionKey
import com.ngoline.easygpg.data.label
import com.ngoline.easygpg.PGPKeyManager
import com.ngoline.easygpg.R
import com.ngoline.easygpg.copyToCharArray
import com.ngoline.easygpg.databinding.FragmentEncryptBinding
import com.ngoline.easygpg.useThenWipe
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.openpgp.PGPEncryptedData
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPLiteralDataGenerator
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import java.util.Date

class EncryptFragment : Fragment() {

    private var _binding: FragmentEncryptBinding? = null

    private lateinit var editTextMessage: EditText
    private lateinit var spinnerPublicKeys: Spinner
    private lateinit var buttonEncryptShare: Button
    private lateinit var keyManager: PGPKeyManager
    private lateinit var publicKeyList: List<PGPPublicKey>

    private val binding get() = _binding!!

    override fun onAttach(context: Context) {
        super.onAttach(context)
        keyManager = PGPKeyManager(context)
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        val encryptViewModel =
            ViewModelProvider(this)[EncryptViewModel::class.java]

        _binding = FragmentEncryptBinding.inflate(inflater, container, false)
        val root: View = binding.root

        editTextMessage = root.findViewById(R.id.editTextMessage)
        spinnerPublicKeys = root.findViewById(R.id.spinnerPublicKeys)
        buttonEncryptShare = root.findViewById(R.id.buttonEncryptShare)

        loadPublicKeys()

        buttonEncryptShare.setOnClickListener {
            val selectedIndex = spinnerPublicKeys.selectedItemPosition
            if (selectedIndex != -1 && selectedIndex < publicKeyList.size) {
                val selectedKey = publicKeyList[selectedIndex]  // Get the public key using the selected index
                // The typed message is copied into a buffer of our own so it can be wiped; what the
                // EditText keeps internally is beyond our reach.
                val message = editTextMessage.text.copyToCharArray()
                // Run encryption in a background thread
                lifecycleScope.launch {
                    val encryptedMessage = withContext(Dispatchers.Default) {
                        message.useThenWipe { keyManager.encryptMessage(it, selectedKey) }
                    }
                    shareEncryptedMessage(encryptedMessage)
                    if (shouldClearFieldsAfterOperation()) {
                        editTextMessage.setText("")
                    }
                }
            } else {
                Toast.makeText(requireContext(), "No public key selected", Toast.LENGTH_SHORT).show()
            }
        }
        return root
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }

    private fun shouldClearFieldsAfterOperation(): Boolean {
        val prefs = PreferenceManager.getDefaultSharedPreferences(requireContext())
        return prefs.getBoolean(getString(R.string.clear_fields_after_operation), true)
    }

    private fun loadPublicKeys() {
        // One entry per key ring, named after its primary key. A ring with no encryption-capable
        // key cannot be encrypted to at all, so it is left out.
        val (labels, keys) = keyManager.getAllPublicKeys()
            .mapNotNull { keyItem -> keyItem.encryptionKey?.let { keyItem.label to it } }
            .unzip()

        publicKeyList = keys

        val adapter =
            ArrayAdapter(requireContext(), android.R.layout.simple_spinner_dropdown_item, labels)
        spinnerPublicKeys.adapter = adapter
    }

    private fun shareEncryptedMessage(encryptedMessage: String) {
        val sendIntent = Intent().apply {
            action = Intent.ACTION_SEND
            putExtra(Intent.EXTRA_TEXT, encryptedMessage)
            type = "text/plain"
        }
        startActivity(Intent.createChooser(sendIntent, "Share via"))
    }
}