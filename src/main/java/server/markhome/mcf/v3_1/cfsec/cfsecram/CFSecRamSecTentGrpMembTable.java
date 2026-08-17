
// Description: Java 25 in-memory RAM DbIO implementation for SecTentGrpMemb.

/*
 *	server.markhome.mcf.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow mark.sobkow@gmail.com
 *	
 *	These files are part of Mark's Code Fractal CFSec.
 *	
 *	Licensed under the Apache License, Version 2.0 (the "License");
 *	you may not use this file except in compliance with the License.
 *	You may obtain a copy of the License at
 *	
 *	http://www.apache.org/licenses/LICENSE-2.0
 *	
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
 *	
 */

package server.markhome.mcf.v3_1.cfsec.cfsecram;

import java.math.*;
import java.sql.*;
import java.text.*;
import java.time.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import server.markhome.mcf.v3_1.cflib.*;
import server.markhome.mcf.v3_1.cflib.dbutil.*;

import server.markhome.mcf.v3_1.cfsec.cfsec.*;
import server.markhome.mcf.v3_1.cfsec.cfsec.buff.*;
import server.markhome.mcf.v3_1.cfsec.cfsecobj.*;

/*
 *	CFSecRamSecTentGrpMembTable in-memory RAM DbIO implementation
 *	for SecTentGrpMemb.
 */
public class CFSecRamSecTentGrpMembTable
	implements ICFSecSecTentGrpMembTable
{
	private ICFSecSchema schema;
	private Map< ICFSecSecTentGrpMembPKey,
				CFSecBuffSecTentGrpMemb > dictByPKey
		= new HashMap< ICFSecSecTentGrpMembPKey,
				CFSecBuffSecTentGrpMemb >();
	private Map< CFSecBuffSecTentGrpMembByTentGrpIdxKey,
				Map< CFSecBuffSecTentGrpMembPKey,
					CFSecBuffSecTentGrpMemb >> dictByTentGrpIdx
		= new HashMap< CFSecBuffSecTentGrpMembByTentGrpIdxKey,
				Map< CFSecBuffSecTentGrpMembPKey,
					CFSecBuffSecTentGrpMemb >>();
	private Map< CFSecBuffSecTentGrpMembByUserIdxKey,
				Map< CFSecBuffSecTentGrpMembPKey,
					CFSecBuffSecTentGrpMemb >> dictByUserIdx
		= new HashMap< CFSecBuffSecTentGrpMembByUserIdxKey,
				Map< CFSecBuffSecTentGrpMembPKey,
					CFSecBuffSecTentGrpMemb >>();

	public CFSecRamSecTentGrpMembTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public CFSecBuffSecTentGrpMemb ensureRec(ICFSecSecTentGrpMemb rec) {
		return (((CFSecBuffSecTentGrpMembFactoryService)(schema.getCFSecBuffFactory().getFactorySecTentGrpMemb())).ensureRec(rec));
	}

	@Override
	public ICFSecSecTentGrpMemb createSecTentGrpMemb( ICFSecAuthorization Authorization,
		ICFSecSecTentGrpMemb iBuff )
	{
		final String S_ProcName = "createSecTentGrpMemb";
		
		CFSecBuffSecTentGrpMemb Buff = (CFSecBuffSecTentGrpMemb)ensureRec(iBuff);
		CFSecBuffSecTentGrpMembPKey pkey = (CFSecBuffSecTentGrpMembPKey)(schema.getCFSecBuffFactory().getFactorySecTentGrpMemb().newPKey());
		pkey.setRequiredSecTentGrpId(Buff.getRequiredSecTentGrpId());
		pkey.setRequiredLoginId(Buff.getRequiredLoginId());
		pkey.setRequiredSecTentGrpId( Buff.getRequiredSecTentGrpId() );
		pkey.setRequiredLoginId( Buff.getRequiredLoginId() );
		Buff.setRequiredContainerGroup( pkey.getRequiredSecTentGrpId() );
		Buff.setRequiredParentUser( pkey.getRequiredLoginId() );
		Buff.setRequiredSecTentGrpId( pkey.getRequiredSecTentGrpId() );
		Buff.setRequiredLoginId( pkey.getRequiredLoginId() );
		CFSecBuffSecTentGrpMembByTentGrpIdxKey keyTentGrpIdx = (CFSecBuffSecTentGrpMembByTentGrpIdxKey)schema.getCFSecBuffFactory().getFactorySecTentGrpMemb().newByTentGrpIdxKey();
		keyTentGrpIdx.setRequiredSecTentGrpId( Buff.getRequiredSecTentGrpId() );

		CFSecBuffSecTentGrpMembByUserIdxKey keyUserIdx = (CFSecBuffSecTentGrpMembByUserIdxKey)schema.getCFSecBuffFactory().getFactorySecTentGrpMemb().newByUserIdxKey();
		keyUserIdx.setRequiredLoginId( Buff.getRequiredLoginId() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		// Validate foreign keys

		{
			boolean allNull = true;
			allNull = false;
			if( ! allNull ) {
				if( null == schema.getTableSecTentGrp().readDerivedByIdIdx( Authorization,
						Buff.getRequiredSecTentGrpId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						S_ProcName,
						"Container",
						"Container",
						"SecTentGrpMembGroup",
						"SecTentGrpMembGroup",
						"SecTentGrp",
						"SecTentGrp",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< CFSecBuffSecTentGrpMembPKey, CFSecBuffSecTentGrpMemb > subdictTentGrpIdx;
		if( dictByTentGrpIdx.containsKey( keyTentGrpIdx ) ) {
			subdictTentGrpIdx = dictByTentGrpIdx.get( keyTentGrpIdx );
		}
		else {
			subdictTentGrpIdx = new HashMap< CFSecBuffSecTentGrpMembPKey, CFSecBuffSecTentGrpMemb >();
			dictByTentGrpIdx.put( keyTentGrpIdx, subdictTentGrpIdx );
		}
		subdictTentGrpIdx.put( pkey, Buff );

		Map< CFSecBuffSecTentGrpMembPKey, CFSecBuffSecTentGrpMemb > subdictUserIdx;
		if( dictByUserIdx.containsKey( keyUserIdx ) ) {
			subdictUserIdx = dictByUserIdx.get( keyUserIdx );
		}
		else {
			subdictUserIdx = new HashMap< CFSecBuffSecTentGrpMembPKey, CFSecBuffSecTentGrpMemb >();
			dictByUserIdx.put( keyUserIdx, subdictUserIdx );
		}
		subdictUserIdx.put( pkey, Buff );

		if (Buff == null) {
			return( null );
		}
		else {
			int classCode = Buff.getClassCode();
			if (classCode == ICFSecSecTentGrpMemb.CLASS_CODE) {
				CFSecBuffSecTentGrpMemb retbuff = ((CFSecBuffSecTentGrpMemb)(schema.getCFSecBuffFactory().getFactorySecTentGrpMemb().newRec()));
				retbuff.set(Buff);
				return( retbuff );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), S_ProcName, "-create-buff-cloning-", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	@Override
	public ICFSecSecTentGrpMemb readDerived( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecTentGrpId,
		String LoginId )
	{
		{	$implJavaOptAtomType$ testSecTentGrpId = SecTentGrpId;
			if (testSecTentGrpId == null) {
				return( null );
			}
		}
		{	$implJavaOptAtomType$ testLoginId = LoginId;
			if (testLoginId == null) {
				return( null );
			}
		}
		CFSecBuffSecTentGrpMembPKey key = (CFSecBuffSecTentGrpMembPKey)(schema.getCFSecBuffFactory().getFactorySecTentGrpMemb().newPKey());
		key.setRequiredSecTentGrpId( SecTentGrpId );
		key.setRequiredLoginId( LoginId );
		return( readDerived( Authorization, key ) );
	}

	public ICFSecSecTentGrpMemb readDerived( ICFSecAuthorization Authorization,
		ICFSecSecTentGrpMembPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecTentGrpMemb.readDerived";
		CFSecBuffSecTentGrpMembPKey key = (CFSecBuffSecTentGrpMembPKey)(schema.getCFSecBuffFactory().getFactorySecTentGrpMemb().newPKey());
		key.setRequiredSecTentGrpId( PKey.getRequiredSecTentGrpId() );
		key.setRequiredLoginId( PKey.getRequiredLoginId() );
		ICFSecSecTentGrpMemb buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecTentGrpMemb lockDerived( ICFSecAuthorization Authorization,
		ICFSecSecTentGrpMembPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecTentGrpMemb.lockDerived";
		CFSecBuffSecTentGrpMembPKey key = (CFSecBuffSecTentGrpMembPKey)(schema.getCFSecBuffFactory().getFactorySecTentGrpMemb().newPKey());
		key.setRequiredSecTentGrpId( PKey.getRequiredSecTentGrpId() );
		key.setRequiredLoginId( PKey.getRequiredLoginId() );
		ICFSecSecTentGrpMemb buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecTentGrpMemb[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamSecTentGrpMemb.readAllDerived";
		ICFSecSecTentGrpMemb[] retList = new ICFSecSecTentGrpMemb[ dictByPKey.values().size() ];
		Iterator< CFSecBuffSecTentGrpMemb > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	@Override
	public ICFSecSecTentGrpMemb[] readDerivedByTentGrpIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecTentGrpId )
	{
		final String S_ProcName = "CFSecRamSecTentGrpMemb.readDerivedByTentGrpIdx";
		CFSecBuffSecTentGrpMembByTentGrpIdxKey key = (CFSecBuffSecTentGrpMembByTentGrpIdxKey)schema.getCFSecBuffFactory().getFactorySecTentGrpMemb().newByTentGrpIdxKey();

		key.setRequiredSecTentGrpId( SecTentGrpId );
		ICFSecSecTentGrpMemb[] recArray;
		if( dictByTentGrpIdx.containsKey( key ) ) {
			Map< CFSecBuffSecTentGrpMembPKey, CFSecBuffSecTentGrpMemb > subdictTentGrpIdx
				= dictByTentGrpIdx.get( key );
			recArray = new ICFSecSecTentGrpMemb[ subdictTentGrpIdx.size() ];
			Iterator< CFSecBuffSecTentGrpMemb > iter = subdictTentGrpIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecBuffSecTentGrpMembPKey, CFSecBuffSecTentGrpMemb > subdictTentGrpIdx
				= new HashMap< CFSecBuffSecTentGrpMembPKey, CFSecBuffSecTentGrpMemb >();
			dictByTentGrpIdx.put( key, subdictTentGrpIdx );
			recArray = new ICFSecSecTentGrpMemb[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecTentGrpMemb[] readDerivedByUserIdx( ICFSecAuthorization Authorization,
		String LoginId )
	{
		final String S_ProcName = "CFSecRamSecTentGrpMemb.readDerivedByUserIdx";
		CFSecBuffSecTentGrpMembByUserIdxKey key = (CFSecBuffSecTentGrpMembByUserIdxKey)schema.getCFSecBuffFactory().getFactorySecTentGrpMemb().newByUserIdxKey();

		key.setRequiredLoginId( LoginId );
		ICFSecSecTentGrpMemb[] recArray;
		if( dictByUserIdx.containsKey( key ) ) {
			Map< CFSecBuffSecTentGrpMembPKey, CFSecBuffSecTentGrpMemb > subdictUserIdx
				= dictByUserIdx.get( key );
			recArray = new ICFSecSecTentGrpMemb[ subdictUserIdx.size() ];
			Iterator< CFSecBuffSecTentGrpMemb > iter = subdictUserIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecBuffSecTentGrpMembPKey, CFSecBuffSecTentGrpMemb > subdictUserIdx
				= new HashMap< CFSecBuffSecTentGrpMembPKey, CFSecBuffSecTentGrpMemb >();
			dictByUserIdx.put( key, subdictUserIdx );
			recArray = new ICFSecSecTentGrpMemb[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecTentGrpMemb readDerivedByIdIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecTentGrpId,
		String LoginId )
	{
		final String S_ProcName = "CFSecRamSecTentGrpMemb.readDerivedByIdIdx() ";
		CFSecBuffSecTentGrpMembPKey key = (CFSecBuffSecTentGrpMembPKey)(schema.getCFSecBuffFactory().getFactorySecTentGrpMemb().newPKey());
		key.setRequiredSecTentGrpId( SecTentGrpId );
		key.setRequiredLoginId( LoginId );
		ICFSecSecTentGrpMemb buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecTentGrpMemb readRec( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecTentGrpId,
		String LoginId )
	{
		CFSecBuffSecTentGrpMembPKey key = (CFSecBuffSecTentGrpMembPKey)(schema.getCFSecBuffFactory().getFactorySecTentGrpMemb().newPKey());
		key.setRequiredSecTentGrpId( SecTentGrpId );
		key.setRequiredLoginId( LoginId );
		return( readRec( Authorization, key ) );
	}

	@Override
	public ICFSecSecTentGrpMemb readRec( ICFSecAuthorization Authorization,
		ICFSecSecTentGrpMembPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecTentGrpMemb.readRec";
		ICFSecSecTentGrpMemb buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecTentGrpMemb.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecTentGrpMemb lockRec( ICFSecAuthorization Authorization,
		ICFSecSecTentGrpMembPKey PKey )
	{
		final String S_ProcName = "lockRec";
		ICFSecSecTentGrpMemb buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecTentGrpMemb.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecTentGrpMemb[] readAllRec( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamSecTentGrpMemb.readAllRec";
		ICFSecSecTentGrpMemb buff;
		ArrayList<ICFSecSecTentGrpMemb> filteredList = new ArrayList<ICFSecSecTentGrpMemb>();
		ICFSecSecTentGrpMemb[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecTentGrpMemb.CLASS_CODE ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecTentGrpMemb[0] ) );
	}

	/**
	 *	Read a page of all the specific SecTentGrpMemb buffer instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific SecTentGrpMemb instances in the database accessible for the Authorization.
	 */
	@Override
	public ICFSecSecTentGrpMemb[] pageAllRec( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 priorSecTentGrpId,
		String priorLoginId )
	{
		final String S_ProcName = "pageAllRec";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	@Override
	public ICFSecSecTentGrpMemb readRecByIdIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecTentGrpId,
		String LoginId )
	{
		final String S_ProcName = "CFSecRamSecTentGrpMemb.readRecByIdIdx() ";
		ICFSecSecTentGrpMemb buff = readDerivedByIdIdx( Authorization,
			SecTentGrpId,
			LoginId );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecTentGrpMemb.CLASS_CODE ) ) {
			return( (ICFSecSecTentGrpMemb)buff );
		}
		else {
			return( null );
		}
	}

	@Override
	public ICFSecSecTentGrpMemb[] readRecByTentGrpIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecTentGrpId )
	{
		final String S_ProcName = "CFSecRamSecTentGrpMemb.readRecByTentGrpIdx() ";
		ICFSecSecTentGrpMemb buff;
		ArrayList<ICFSecSecTentGrpMemb> filteredList = new ArrayList<ICFSecSecTentGrpMemb>();
		ICFSecSecTentGrpMemb[] buffList = readDerivedByTentGrpIdx( Authorization,
			SecTentGrpId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecTentGrpMemb.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecTentGrpMemb)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecTentGrpMemb[0] ) );
	}

	@Override
	public ICFSecSecTentGrpMemb[] readRecByUserIdx( ICFSecAuthorization Authorization,
		String LoginId )
	{
		final String S_ProcName = "CFSecRamSecTentGrpMemb.readRecByUserIdx() ";
		ICFSecSecTentGrpMemb buff;
		ArrayList<ICFSecSecTentGrpMemb> filteredList = new ArrayList<ICFSecSecTentGrpMemb>();
		ICFSecSecTentGrpMemb[] buffList = readDerivedByUserIdx( Authorization,
			LoginId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecTentGrpMemb.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecTentGrpMemb)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecTentGrpMemb[0] ) );
	}

	/**
	 *	Read a page array of the specific SecTentGrpMemb buffer instances identified by the duplicate key TentGrpIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecTentGrpId	The SecTentGrpMemb key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecTentGrpMemb[] pageRecByTentGrpIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecTentGrpId,
		ICFLibKeyHash256 priorSecTentGrpId,
		String priorLoginId )
	{
		final String S_ProcName = "pageRecByTentGrpIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific SecTentGrpMemb buffer instances identified by the duplicate key UserIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	LoginId	The SecTentGrpMemb key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecTentGrpMemb[] pageRecByUserIdx( ICFSecAuthorization Authorization,
		String LoginId,
		ICFLibKeyHash256 priorSecTentGrpId,
		String priorLoginId )
	{
		final String S_ProcName = "pageRecByUserIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	@Override
	public ICFSecSecTentGrpMemb updateSecTentGrpMemb( ICFSecAuthorization Authorization,
		ICFSecSecTentGrpMemb iBuff )
	{
		CFSecBuffSecTentGrpMemb Buff = (CFSecBuffSecTentGrpMemb)ensureRec(iBuff);
		CFSecBuffSecTentGrpMembPKey pkey = (CFSecBuffSecTentGrpMembPKey)(schema.getCFSecBuffFactory().getFactorySecTentGrpMemb().newPKey());
		pkey = (CFSecBuffSecTentGrpMembPKey)Buff.getPKey();
		CFSecBuffSecTentGrpMemb existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateSecTentGrpMemb",
				"Existing record not found",
				"Existing record not found",
				"SecTentGrpMemb",
				"SecTentGrpMemb",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateSecTentGrpMemb",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffSecTentGrpMembByTentGrpIdxKey existingKeyTentGrpIdx = (CFSecBuffSecTentGrpMembByTentGrpIdxKey)schema.getCFSecBuffFactory().getFactorySecTentGrpMemb().newByTentGrpIdxKey();
		existingKeyTentGrpIdx.setRequiredSecTentGrpId( existing.getRequiredSecTentGrpId() );

		CFSecBuffSecTentGrpMembByTentGrpIdxKey newKeyTentGrpIdx = (CFSecBuffSecTentGrpMembByTentGrpIdxKey)schema.getCFSecBuffFactory().getFactorySecTentGrpMemb().newByTentGrpIdxKey();
		newKeyTentGrpIdx.setRequiredSecTentGrpId( Buff.getRequiredSecTentGrpId() );

		CFSecBuffSecTentGrpMembByUserIdxKey existingKeyUserIdx = (CFSecBuffSecTentGrpMembByUserIdxKey)schema.getCFSecBuffFactory().getFactorySecTentGrpMemb().newByUserIdxKey();
		existingKeyUserIdx.setRequiredLoginId( existing.getRequiredLoginId() );

		CFSecBuffSecTentGrpMembByUserIdxKey newKeyUserIdx = (CFSecBuffSecTentGrpMembByUserIdxKey)schema.getCFSecBuffFactory().getFactorySecTentGrpMemb().newByUserIdxKey();
		newKeyUserIdx.setRequiredLoginId( Buff.getRequiredLoginId() );

		// Check unique indexes

		// Validate foreign keys

		{
			boolean allNull = true;

			if( allNull ) {
				if( null == schema.getTableSecTentGrp().readDerivedByIdIdx( Authorization,
						Buff.getRequiredSecTentGrpId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateSecTentGrpMemb",
						"Container",
						"Container",
						"SecTentGrpMembGroup",
						"SecTentGrpMembGroup",
						"SecTentGrp",
						"SecTentGrp",
						null );
				}
			}
		}

		// Update is valid

		Map< CFSecBuffSecTentGrpMembPKey, CFSecBuffSecTentGrpMemb > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		subdict = dictByTentGrpIdx.get( existingKeyTentGrpIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByTentGrpIdx.containsKey( newKeyTentGrpIdx ) ) {
			subdict = dictByTentGrpIdx.get( newKeyTentGrpIdx );
		}
		else {
			subdict = new HashMap< CFSecBuffSecTentGrpMembPKey, CFSecBuffSecTentGrpMemb >();
			dictByTentGrpIdx.put( newKeyTentGrpIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictByUserIdx.get( existingKeyUserIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByUserIdx.containsKey( newKeyUserIdx ) ) {
			subdict = dictByUserIdx.get( newKeyUserIdx );
		}
		else {
			subdict = new HashMap< CFSecBuffSecTentGrpMembPKey, CFSecBuffSecTentGrpMemb >();
			dictByUserIdx.put( newKeyUserIdx, subdict );
		}
		subdict.put( pkey, Buff );

		return(Buff);
	}

	@Override
	public void deleteSecTentGrpMemb( ICFSecAuthorization Authorization,
		ICFSecSecTentGrpMemb iBuff )
	{
		final String S_ProcName = "CFSecRamSecTentGrpMembTable.deleteSecTentGrpMemb() ";
		CFSecBuffSecTentGrpMemb Buff = (CFSecBuffSecTentGrpMemb)ensureRec(iBuff);
		int classCode;
		CFSecBuffSecTentGrpMembPKey pkey = (CFSecBuffSecTentGrpMembPKey)(Buff.getPKey());
		CFSecBuffSecTentGrpMemb existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteSecTentGrpMemb",
				pkey );
		}
		CFSecBuffSecTentGrpMembByTentGrpIdxKey keyTentGrpIdx = (CFSecBuffSecTentGrpMembByTentGrpIdxKey)schema.getCFSecBuffFactory().getFactorySecTentGrpMemb().newByTentGrpIdxKey();
		keyTentGrpIdx.setRequiredSecTentGrpId( existing.getRequiredSecTentGrpId() );

		CFSecBuffSecTentGrpMembByUserIdxKey keyUserIdx = (CFSecBuffSecTentGrpMembByUserIdxKey)schema.getCFSecBuffFactory().getFactorySecTentGrpMemb().newByUserIdxKey();
		keyUserIdx.setRequiredLoginId( existing.getRequiredLoginId() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFSecBuffSecTentGrpMembPKey, CFSecBuffSecTentGrpMemb > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByTentGrpIdx.get( keyTentGrpIdx );
		subdict.remove( pkey );

		subdict = dictByUserIdx.get( keyUserIdx );
		subdict.remove( pkey );

	}
	@Override
	public void deleteSecTentGrpMembByIdIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecTentGrpId,
		String LoginId )
	{
		CFSecBuffSecTentGrpMembPKey key = (CFSecBuffSecTentGrpMembPKey)(schema.getCFSecBuffFactory().getFactorySecTentGrpMemb().newPKey());
		key.setRequiredSecTentGrpId( SecTentGrpId );
		key.setRequiredLoginId( LoginId );
		deleteSecTentGrpMembByIdIdx( Authorization, key );
	}

	@Override
	public void deleteSecTentGrpMembByIdIdx( ICFSecAuthorization Authorization,
		ICFSecSecTentGrpMembPKey PKey )
	{
		CFSecBuffSecTentGrpMembPKey key = (CFSecBuffSecTentGrpMembPKey)(schema.getCFSecBuffFactory().getFactorySecTentGrpMemb().newPKey());
		key.setRequiredSecTentGrpId( PKey.getRequiredSecTentGrpId() );
		key.setRequiredLoginId( PKey.getRequiredLoginId() );
		CFSecBuffSecTentGrpMembPKey argKey = key;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecBuffSecTentGrpMemb cur;
		LinkedList<CFSecBuffSecTentGrpMemb> matchSet = new LinkedList<CFSecBuffSecTentGrpMemb>();
		Iterator<CFSecBuffSecTentGrpMemb> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecTentGrpMemb> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecTentGrpMemb)(schema.getTableSecTentGrpMemb().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecTentGrpId(),
				cur.getRequiredLoginId() ));
			deleteSecTentGrpMemb( Authorization, cur );
		}
	}

	@Override
	public void deleteSecTentGrpMembByTentGrpIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 argSecTentGrpId )
	{
		CFSecBuffSecTentGrpMembByTentGrpIdxKey key = (CFSecBuffSecTentGrpMembByTentGrpIdxKey)schema.getCFSecBuffFactory().getFactorySecTentGrpMemb().newByTentGrpIdxKey();
		key.setRequiredSecTentGrpId( argSecTentGrpId );
		deleteSecTentGrpMembByTentGrpIdx( Authorization, key );
	}

	@Override
	public void deleteSecTentGrpMembByTentGrpIdx( ICFSecAuthorization Authorization,
		ICFSecSecTentGrpMembByTentGrpIdxKey argKey )
	{
		CFSecBuffSecTentGrpMemb cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecTentGrpMemb> matchSet = new LinkedList<CFSecBuffSecTentGrpMemb>();
		Iterator<CFSecBuffSecTentGrpMemb> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecTentGrpMemb> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecTentGrpMemb)(schema.getTableSecTentGrpMemb().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecTentGrpId(),
				cur.getRequiredLoginId() ));
			deleteSecTentGrpMemb( Authorization, cur );
		}
	}

	@Override
	public void deleteSecTentGrpMembByUserIdx( ICFSecAuthorization Authorization,
		String argLoginId )
	{
		CFSecBuffSecTentGrpMembByUserIdxKey key = (CFSecBuffSecTentGrpMembByUserIdxKey)schema.getCFSecBuffFactory().getFactorySecTentGrpMemb().newByUserIdxKey();
		key.setRequiredLoginId( argLoginId );
		deleteSecTentGrpMembByUserIdx( Authorization, key );
	}

	@Override
	public void deleteSecTentGrpMembByUserIdx( ICFSecAuthorization Authorization,
		ICFSecSecTentGrpMembByUserIdxKey argKey )
	{
		CFSecBuffSecTentGrpMemb cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecTentGrpMemb> matchSet = new LinkedList<CFSecBuffSecTentGrpMemb>();
		Iterator<CFSecBuffSecTentGrpMemb> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecTentGrpMemb> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecTentGrpMemb)(schema.getTableSecTentGrpMemb().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecTentGrpId(),
				cur.getRequiredLoginId() ));
			deleteSecTentGrpMemb( Authorization, cur );
		}
	}
}
