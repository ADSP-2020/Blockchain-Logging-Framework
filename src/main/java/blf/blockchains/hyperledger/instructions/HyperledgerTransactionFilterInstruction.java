package blf.blockchains.hyperledger.instructions;

import blf.blockchains.hyperledger.state.HyperledgerProgramState;
import blf.core.exceptions.ExceptionHandler;
import blf.core.exceptions.ProgramException;
import blf.core.instructions.FilterInstruction;
import blf.core.interfaces.Instruction;
import blf.core.state.ProgramState;
import blf.core.values.ValueStore;
import org.hyperledger.fabric.sdk.BlockEvent;
import org.hyperledger.fabric.sdk.BlockInfo;
import org.hyperledger.fabric.sdk.ChaincodeEvent;

import java.util.List;
import java.util.logging.Logger;

/**
 * HyperledgerTransactionFilterInstruction is an Instruction for the Hyperledger log extraction mode of the Blockchain
 * Logging Framework. It extracts the specified transactions (specified by transaction sender and/or recipient)
 * from the current Block and stores the extracted transaction parameters in the ValueStore.
 */
public class HyperledgerTransactionFilterInstruction extends FilterInstruction {

    private final Logger logger;
    private ExceptionHandler exceptionHandler;

    private final List<String> sendersAddressList;
    private final List<String> recipientsAddressList;

    private static final String TRANSACTION_ID = "transaction.id";
    private static final String TRANSACTION_HASH = "transaction.hash";
    private static final String TRANSACTION_CREATOR_MSPID = "transaction.creator.mspid";
    private static final String TRANSACTION_CREATOR_ID = "transaction.creator.id";
    private static final String TRANSACTION_PEER_NAME = "transaction.peer.name";
    private static final String TRANSACTION_PEER_HASH = "transaction.peer.hash";
    private static final String TRANSACTION_PEER_URL = "transaction.peer.url";
    private static final String TRANSACTION_CHAINCODE_ID = "transaction.chaincode.id";
    private static final String TRANSACTION_RESPONSE_MESSAGE = "transaction.response.message";
    private static final String TRANSACTION_RESPONSE_STATUS = "transaction.response.status";
    private static final String TRANSACTION_ENDORSEMENT_COUNT = "transaction.endorsement.count";

    /**
     * Constructs a HyperledgerTransactionFilterInstruction.
     *
     * @param sendersAddressList    The list of all sender addresses the user requested in the manifest (might be empty).
     * @param recipientsAddressList The list of all recipient addresses the user requested in the manifest (always non-empty).
     */
    public HyperledgerTransactionFilterInstruction(
            final List<String> sendersAddressList,
            final List<String> recipientsAddressList,
            List<Instruction> nestedInstructions
    ) {
        super(nestedInstructions);

        this.sendersAddressList = sendersAddressList;
        this.recipientsAddressList = recipientsAddressList;

        this.logger = Logger.getLogger(HyperledgerTransactionFilterInstruction.class.getName());
    }

    /**
     * execute is called once the program is constructed from the manifest. It contains the logic for extracting an
     * event from the Hyperledger block that the BLF is currently analyzing. It is called by the Program class.
     *
     * @param state The current ProgramState of the BLF, provided by the Program when called.
     * @throws ProgramException never explicitly
     */
    @Override
    public void execute(ProgramState state) throws ProgramException {
        // init exception handler
        this.exceptionHandler = state.getExceptionHandler();

        HyperledgerProgramState hyperledgerProgramState = (HyperledgerProgramState) state;

        // TODO: implement HyperledgerTransactionFilterInstruction logic here
        String infoMsg = String.format(
                "============== HyperledgerTransactionFilterInstruction ==============\n"
                        + "sendersAddressList = %s \n"
                        + "recipientsAddressList = %s \n",
                this.sendersAddressList,
                this.recipientsAddressList
        );

        logger.info(infoMsg);

        BlockEvent be = hyperledgerProgramState.getCurrentBlock();
        if (be == null) {
            this.exceptionHandler.handleExceptionAndDecideOnAbort("Expected block, received null", new NullPointerException());
            return;
        }

        for (BlockEvent.TransactionEvent te : be.getTransactionEvents()) {
            BlockInfo.EnvelopeInfo.IdentitiesInfo indentityInfo = te.getCreator();
            // TODO: should we add getMspid as possible filter candidates here?
            if(!sendersAddressList.contains(indentityInfo.getId())) {
                for (BlockInfo.TransactionEnvelopeInfo.TransactionActionInfo ti : te.getTransactionActionInfos()) {
                    if(recipientsAddressList.contains(ti.getChaincodeIDName())){
                        ValueStore valueStore = state.getValueStore();
                        valueStore.setValue(TRANSACTION_HASH, te.hashCode());
                        valueStore.setValue(TRANSACTION_ID, te.getTransactionID());
                        valueStore.setValue(TRANSACTION_CREATOR_ID, indentityInfo.getId());
                        valueStore.setValue(TRANSACTION_CREATOR_MSPID, indentityInfo.getMspid());
                        valueStore.setValue(TRANSACTION_PEER_NAME, te.getPeer().getName());
                        valueStore.setValue(TRANSACTION_PEER_HASH, te.getPeer().hashCode());
                        valueStore.setValue(TRANSACTION_PEER_URL, te.getPeer().getUrl());
                        valueStore.setValue(TRANSACTION_CHAINCODE_ID, ti.getChaincodeIDName());
                        valueStore.setValue(TRANSACTION_RESPONSE_MESSAGE, ti.getResponseMessage());
                        valueStore.setValue(TRANSACTION_ENDORSEMENT_COUNT, ti.getEndorsementsCount());
                        valueStore.setValue(TRANSACTION_RESPONSE_STATUS, ti.getResponseStatus());
                        this.executeNestedInstructions(hyperledgerProgramState);
                    }
                }
            }
        }
    }
}
